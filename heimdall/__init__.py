"""Heimdall — a self-discovering pentest library for FastAPI applications.

The watchman that sees what approaches: point it at a running FastAPI app and it
learns the app's routes, auth shape and (optionally) its secrets from the
source tree, mints principals through the real login flow, then runs the OWASP
Top-10 exploit modules against the live target and writes a report.

Programmatic use:

    import heimdall

    result = heimdall.assess(
        base_url="http://127.0.0.1:8000",
        source_path="/path/to/the app",          # optional white-box
        credentials=[("admin", "admin", "admin@ec.fr", "hunter2")],  # label,role,id,pw
    )
    print(result.counts())
    print(result.report_paths)

Or drive discovery on its own:

    profile = heimdall.discover("http://127.0.0.1:8000", source_path="…")
    print(heimdall.summarize(profile))
"""

from __future__ import annotations

from .bootstrap.principals import Cred
from .config import TargetConfig
from .discovery import discover, summarize
from .runner import RunResult, run

__version__ = "0.1.0"

__all__ = [
    "assess",
    "run",
    "discover",
    "summarize",
    "TargetConfig",
    "Cred",
    "RunResult",
]


def assess(
    base_url: str,
    *,
    source_path: str | None = None,
    name: str | None = None,
    credentials: list | None = None,
    launch: str | None = None,
    launch_cwd: str | None = None,
    authorized: bool = False,
    safe: bool = False,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    out_dir: str | None = None,
    make_attacker: bool = True,
) -> RunResult:
    """One-call assessment. ``credentials`` is a list of ``Cred`` or
    ``(label, role, identifier, password)`` tuples."""
    creds = []
    for c in credentials or []:
        if isinstance(c, Cred):
            creds.append(c)
        else:
            label, role, ident, pw = c
            creds.append(Cred(label=label, role=role, identifier=ident, password=pw))
    cfg = TargetConfig(
        base_url=base_url, name=name, source_path=source_path,
        launch=launch, launch_cwd=launch_cwd, credentials=creds,
        authorized=authorized, make_attacker=make_attacker,
    )
    return run(cfg, out_dir=out_dir, only=only, skip=skip, safe=safe)
