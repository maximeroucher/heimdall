"""Optionally boot the target app and wait until it answers.

Heimdall can run against an already-running server (the common case) or launch
one from a command you provide. Launching is best-effort convenience; the DB
must already be reachable/seeded by that command — Heimdall does not invent an
app-specific seed.
"""

from __future__ import annotations

import subprocess
import time

import requests

_HEALTH_PATHS = ["/health", "/healthz", "/information", "/", "/openapi.json"]


def wait_for_server(base_url: str, timeout: float = 60.0) -> bool:
    base = base_url.rstrip("/")
    end = time.time() + timeout
    while time.time() < end:
        for path in _HEALTH_PATHS:
            try:
                r = requests.get(f"{base}{path}", timeout=3)
                if r.status_code < 500:
                    return True
            except requests.RequestException:
                pass
        time.sleep(1.0)
    return False


def launch(command: str, cwd: str | None = None, env: dict | None = None) -> subprocess.Popen:
    """Start the target via a shell command; returns the Popen (caller kills it)."""
    import os
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.Popen(
        command, shell=True, cwd=cwd, env=full_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
