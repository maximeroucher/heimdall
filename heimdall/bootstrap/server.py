"""Optionally boot the target app and wait until it answers.

Heimdall can run against an already-running server (the common case) or launch
one from a command you provide. Launching is best-effort convenience; the DB
must already be reachable/seeded by that command — Heimdall does not invent an
app-specific seed.

Heavier apps run database migrations and seed fixtures on boot, so first-start
can take a while — the wait timeout is generous and configurable, the target's
own stdout/stderr is captured to a log so a failed boot is diagnosable, and an
early process exit is detected so we fail fast instead of polling a dead port.
"""

from __future__ import annotations

import os
import subprocess
import time

import requests

_HEALTH_PATHS = ["/health", "/healthz", "/information", "/", "/openapi.json"]


def wait_for_server(base_url: str, timeout: float = 180.0,
                    proc: subprocess.Popen | None = None) -> bool:
    """Poll the target until any path answers (<500) or the deadline passes.

    A response — even a 404 at ``/`` — means the server is up. If ``proc`` is
    given and it exits before the target answers, stop immediately: a crashed
    boot will never become reachable, so waiting out the full timeout is pointless.
    """
    base = base_url.rstrip("/")
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False  # target process died during boot — fail fast
        for path in _HEALTH_PATHS:
            try:
                r = requests.get(f"{base}{path}", timeout=3)
                if r.status_code < 500:
                    return True
            except requests.RequestException:
                pass
        time.sleep(1.0)
    return False


def launch(command: str, cwd: str | None = None, env: dict | None = None,
           log_path: str | None = None) -> subprocess.Popen:
    """Start the target via a shell command; returns the Popen (caller kills it).

    The target's stdout+stderr go to ``log_path`` when given (so a failed or slow
    boot is diagnosable) and are otherwise discarded.
    """
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    out = open(log_path, "wb") if log_path else subprocess.DEVNULL
    return subprocess.Popen(
        command, shell=True, cwd=cwd, env=full_env,
        stdout=out, stderr=subprocess.STDOUT,
    )


def log_tail(log_path: str | None, lines: int = 25) -> str:
    """Return the last ``lines`` of a captured target log, for failure output."""
    if not log_path or not os.path.exists(log_path):
        return ""
    try:
        with open(log_path, "rb") as fh:
            tail = fh.read().decode("utf-8", "replace").splitlines()[-lines:]
    except OSError:
        return ""
    return "\n".join(tail)
