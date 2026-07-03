"""Target guardrail: a pentest toolkit that can be aimed at prod by accident is
itself a vulnerability. By default Heimdall refuses any non-loopback target."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def is_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = {ai[4][0] for ai in infos}
        return bool(addrs) and all(ipaddress.ip_address(a).is_loopback for a in addrs)
    except (socket.gaierror, ValueError):
        return host in ("localhost", "127.0.0.1", "::1")


def assert_target_allowed(base_url: str, authorized: bool) -> None:
    host = urlparse(base_url).hostname or ""
    if is_loopback(host) or authorized:
        return
    raise SystemExit(
        f"[GUARDRAIL] Target {base_url!r} is not loopback and no authorization was given.\n"
        f"Re-run with --i-have-authorization ONLY if you own or are explicitly\n"
        f"authorized to test this host. Never point Heimdall at third-party systems."
    )
