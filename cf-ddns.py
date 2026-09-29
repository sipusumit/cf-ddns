#!/usr/bin/env python3
"""cf-ddns: Cloudflare AAAA updater driven by local IPv6 address changes. Stdlib only."""

import argparse
import ipaddress
import json
import logging
import os
import select
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CF_API = "https://api.cloudflare.com/client/v4"
IF_INET6 = "/proc/net/if_inet6"
RTMGRP_IPV6_IFADDR = 0x100  # netlink multicast group: IPv6 address add/remove

# flags from linux/if_addr.h
IFA_F_TEMPORARY = 0x01
IFA_F_DADFAILED = 0x08
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE = 0x40

log = logging.getLogger("cf-ddns")
stop_event = threading.Event()


class CloudflareError(Exception):
    pass


# ---------- local detection ----------

def local_ipv6(interface=None, prefix=None, allow_temporary=False):
    """Return the chosen global IPv6 address (IPv6Address) or None."""
    candidates = []
    with open(IF_INET6) as f:
        for line in f:
            hexaddr, _idx, _plen, scope, flags, ifname = line.split()
            if ifname == "lo" or (interface and ifname != interface):
                continue
            if int(scope, 16) != 0:  # 0 = global scope
                continue
            flags = int(flags, 16)
            if flags & (IFA_F_DADFAILED | IFA_F_DEPRECATED | IFA_F_TENTATIVE):
                continue
            if flags & IFA_F_TEMPORARY and not allow_temporary:
                continue
            ip = ipaddress.IPv6Address(int(hexaddr, 16))
            if not ip.is_global:  # drops ULA (fc00::/7), link-local, etc.
                continue
            if prefix and ip not in prefix:
                continue
            candidates.append(ip)
    if not candidates:
        return None
    candidates.sort()
    if len(candidates) > 1:
        log.debug("Multiple candidates %s, using %s (set 'prefix' to choose)",
                  [str(c) for c in candidates], candidates[0])
    return candidates[0]


def open_netlink():
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        s.bind((0, RTMGRP_IPV6_IFADDR))
        s.setblocking(False)
        return s
    except OSError as e:
        log.warning("Netlink unavailable (%s); falling back to polling only", e)
        return None


def wait_for_change(nl, timeout):
    """Sleep up to `timeout` seconds, returning early on an address event."""
    if nl is None:
        stop_event.wait(timeout)
        return
    end = time.monotonic() + timeout
    while not stop_event.is_set():
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        ready, _, _ = select.select([nl], [], [], min(remaining, 1.0))
        if ready:
            try:
                while True:
                    nl.recv(65536)  # drain queued events
            except BlockingIOError:
                pass
            stop_event.wait(2)  # debounce: let SLAAC/DHCPv6 settle
            return


# ---------- Cloudflare ----------

class Cloudflare:
    def __init__(self, token):
        self.headers = {"Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"}

    def call(self, method, path, params=None, body=None):
        url = CF_API + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=self.headers)
        try:
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    raw = r.read().decode()
            except urllib.error.HTTPError as e:
                raw = e.read().decode()  # error details are in the body
            payload = json.loads(raw)
        except Exception as e:
            raise CloudflareError(f"request failed: {e}") from e
        if not payload.get("success"):
            raise CloudflareError(f"{method} {path}: {payload.get('errors')}")
        return payload["result"]

    def zone_id(self, zone):
        res = self.call("GET", "/zones", {"name": zone})
        if not res:
            raise CloudflareError(f"zone '{zone}' not found (check token permissions)")
        return res[0]["id"]

    def upsert_aaaa(self, zid, name, ip, ttl, proxied):
        res = self.call("GET", f"/zones/{zid}/dns_records", {"name": name, "type": "AAAA"})
        body = {"type": "AAAA", "name": name, "content": ip, "ttl": ttl, "proxied": proxied}
        if not res:
            self.call("POST", f"/zones/{zid}/dns_records", body=body)
            return "created"
        rec = res[0]
        # compare as parsed addresses: Cloudflare may return a different textual form
        same_ip = ipaddress.IPv6Address(rec["content"]) == ipaddress.IPv6Address(ip)
        if same_ip and rec.get("proxied") == proxied and (proxied or rec["ttl"] == ttl):
            return "unchanged"
        self.call("PATCH", f"/zones/{zid}/dns_records/{rec['id']}", body=body)
        return "updated"


# ---------- main ----------

def load_config(path, need_token=True):
    with open(path) as f:
        cfg = json.load(f)
    cfg["api_token"] = os.environ.get("CF_API_TOKEN") or cfg.get("api_token")
    cfg.setdefault("interface", None)
    cfg.setdefault("prefix", None)
    cfg.setdefault("allow_temporary", False)
    cfg.setdefault("check_interval", 60)     # polling fallback (seconds)
    cfg.setdefault("resync_interval", 3600)  # force Cloudflare check (seconds)
    cfg.setdefault("retry_interval", 30)     # after a failed update
    cfg.setdefault("ttl", 1)                 # 1 = automatic
    cfg.setdefault("proxied", False)
    cfg["prefix"] = ipaddress.IPv6Network(cfg["prefix"]) if cfg["prefix"] else None
    if need_token:
        if not cfg["api_token"]:
            sys.exit("No API token: set api_token in config or CF_API_TOKEN env var")
        if not cfg.get("zone") or not cfg.get("records"):
            sys.exit("Config needs 'zone' and a non-empty 'records' list")
    return cfg


def main():
    ap = argparse.ArgumentParser(description="Cloudflare IPv6 DDNS daemon")
    ap.add_argument("-c", "--config", default="/etc/cf-ddns/config.json")
    ap.add_argument("--detect", action="store_true",
                    help="print the detected IPv6 address and exit (no Cloudflare calls)")
    ap.add_argument("--once", action="store_true", help="update once and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s", stream=sys.stdout)

    cfg = load_config(args.config, need_token=not args.detect)

    if args.detect:
        ip = local_ipv6(cfg["interface"], cfg["prefix"], cfg["allow_temporary"])
        print(ip if ip else "no suitable global IPv6 address found")
        return

    cf = Cloudflare(cfg["api_token"])
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop_event.set())

    nl = open_netlink()
    zid = None
    last_ip, synced_at, failing, missing_logged = None, 0.0, False, False
    log.info("Started: zone=%s records=%s interface=%s",
             cfg["zone"], cfg["records"], cfg["interface"] or "any")

    while not stop_event.is_set():
        failing = False
        try:
            ip = local_ipv6(cfg["interface"], cfg["prefix"], cfg["allow_temporary"])
            now = time.monotonic()
            if ip is None:
                if not missing_logged:
                    log.warning("No suitable global IPv6 address; leaving DNS untouched")
                    missing_logged = True
            else:
                missing_logged = False
                ip_s = str(ip)
                if ip_s != last_ip or now - synced_at >= cfg["resync_interval"]:
                    if zid is None:
                        zid = cf.zone_id(cfg["zone"])
                    ok = True
                    for name in cfg["records"]:
                        try:
                            res = cf.upsert_aaaa(zid, name, ip_s, cfg["ttl"], cfg["proxied"])
                            if res != "unchanged":
                                log.info("AAAA %s %s -> %s", name, res, ip_s)
                        except CloudflareError as e:
                            log.error("AAAA %s: %s", name, e)
                            ok = False
                    if ok:
                        last_ip, synced_at = ip_s, now
                    else:
                        failing = True
        except CloudflareError as e:
            log.error("%s", e)
            failing = True
        except Exception:
            log.exception("Unexpected error")
            failing = True

        if args.once:
            break
        wait_for_change(nl, cfg["retry_interval"] if failing else cfg["check_interval"])

    log.info("Stopped")


if __name__ == "__main__":
    main()