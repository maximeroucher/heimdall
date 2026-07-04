"""A05 / API9 — Improper inventory: exposed sensitive paths.

Beyond the documented API surface, deployments accidentally expose files and
debug endpoints that were never meant to be public: a committed ``.git``
directory (whole source + history), a ``.env`` (every secret), a Spring-style
``/actuator/env``, a Prometheus ``/metrics``, a database dump left in the web
root. These aren't in the OpenAPI spec, so only path probing finds them.

To stay false-positive-free against SPAs that answer 200 with ``index.html`` for
*any* path, the module (1) baselines an unlikely random path, and (2) requires a
**content signature** — ``.git/HEAD`` must actually start with ``ref:``, ``.env``
must look like ``KEY=value``, ``/metrics`` must be Prometheus text — not merely a
200. Probes are unauthenticated GETs (the risk is public exposure) and read-only.
"""

from __future__ import annotations

import re

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

# (path, signature regex | None, severity, label). Signature None => rely on a
# 200 that differs from the catch-all baseline (used only for high-risk paths).
_PROBES = [
    (".git/HEAD", re.compile(r"^ref:\s*refs/"), "HIGH", "Git repository (source + history)"),
    (".git/config", re.compile(r"\[core\]"), "HIGH", "Git config"),
    (".env", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*="), "HIGH", "Environment file (secrets)"),
    (".env.local", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*="), "HIGH", "Environment file"),
    (".env.production", re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*="), "HIGH", "Environment file"),
    ("config.json", re.compile(
        r"""["'](?:password|secret|secret[_-]?key|access[_-]?key|api[_-]?key|"""
        r"""private[_-]?key|client[_-]?secret|token|auth[_-]?token)["']\s*:\s*"""
        r"""["'][^"']{12,}["']""", re.I), "HIGH", "Config with secrets"),
    (".aws/credentials", re.compile(r"aws_access_key_id", re.I), "HIGH", "AWS credentials"),
    ("actuator/env", re.compile(r"propertySources|systemProperties"), "HIGH", "Spring actuator env"),
    ("actuator", re.compile(r"\"_links\"|/actuator/health"), "MEDIUM", "Spring actuator index"),
    ("metrics", re.compile(r"(?m)^# (HELP|TYPE) "), "MEDIUM", "Prometheus metrics"),
    ("server-status", re.compile(r"Apache Server Status"), "MEDIUM", "Apache server-status"),
    ("phpinfo.php", re.compile(r"phpinfo\(\)|PHP Version"), "MEDIUM", "phpinfo()"),
    (".DS_Store", re.compile(r"Bud1"), "LOW", "macOS .DS_Store (path leak)"),
    ("backup.sql", re.compile(r"(?i)INSERT INTO|CREATE TABLE|PostgreSQL database dump"), "HIGH", "SQL dump"),
    ("dump.sql", re.compile(r"(?i)INSERT INTO|CREATE TABLE"), "HIGH", "SQL dump"),
    ("db.sqlite3", re.compile(r"^SQLite format 3"), "HIGH", "SQLite database file"),
    ("app.db", re.compile(r"^SQLite format 3"), "HIGH", "SQLite database file"),
]
_TIMEOUT = 8


@module("improper-inventory", "Improper Inventory (Sensitive Paths)")
def run(ctx: Context) -> None:
    catchall = _catchall_status(ctx)
    if catchall == "unreachable":
        ctx.note("improper-inventory: base URL not reachable for path probing")
        return

    hits: list[dict] = []
    for path, sig, sev, label in _PROBES:
        rec = _probe(ctx, path, sig, sev, label, catchall)
        if rec:
            hits.append(rec)

    ctx.note(f"improper-inventory: probed {len(_PROBES)} sensitive path(s); "
             f"{len(hits)} exposed (catch-all baseline: {catchall})")
    if hits:
        _report(ctx, hits)
    else:
        _report_safe(ctx)


def _catchall_status(ctx: Context):
    """Probe an unlikely path; if it returns 200 the app is a catch-all SPA and we
    must rely on content signatures, not status codes."""
    try:
        r = ctx.get("/heimdall-nonexistent-a9-probe-x7", timeout=_TIMEOUT,
                    retry_429=False)
    except requests.RequestException:
        return "unreachable"
    return "200-catchall" if r.status_code == 200 else "404-clean"


def _probe(ctx, path, sig, sev, label, catchall) -> dict | None:
    try:
        r = ctx.get("/" + path, timeout=_TIMEOUT, retry_429=False)
    except requests.RequestException:
        return None
    if r.status_code >= 400:
        return None
    try:
        body = r.text or ""
    except Exception:  # noqa: BLE001
        body = ""
    if sig is not None:
        if sig.search(body[:4000]):
            return {"path": path, "label": label, "severity": sev,
                    "status": r.status_code, "sample": _snip(body, sig)}
        return None
    # No signature: only trust a 200 when the app is NOT a catch-all.
    if catchall == "404-clean":
        return {"path": path, "label": label, "severity": sev,
                "status": r.status_code, "sample": body[:80]}
    return None


def _snip(body: str, sig) -> str:
    m = sig.search(body[:4000])
    if not m:
        return body[:80].replace("\n", " ")
    i = m.start()
    return body[max(0, i - 10):i + 60].replace("\n", " ")


# ── findings ─────────────────────────────────────────────────────────────────

_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _report(ctx: Context, hits: list[dict]) -> None:
    hits.sort(key=lambda h: _ORDER.get(h["severity"], 9))
    worst = hits[0]["severity"]
    lines = [f"  /{h['path']}  →  HTTP {h['status']}  [{h['label']}]  "
             f"«{h['sample'].strip()}»" for h in hits[:15]]
    ctx.finding(
        id="a05-exposed-sensitive-path",
        owasp="A05", severity=worst,
        title=(f"{len(hits)} sensitive path(s) exposed — e.g. /{hits[0]['path']} "
               f"({hits[0]['label']})"),
        summary=(
            "Files / debug endpoints that are not part of the API surface are "
            "reachable and returned their real contents (matched by content "
            "signature, not just a 200). Depending on which, this leaks source "
            "code and history (.git), every secret (.env / actuator/env / config), "
            "cloud credentials, a full database dump, or internal telemetry "
            "(/metrics). Remove these from the deployment, block dotfiles and "
            "backup extensions at the reverse proxy, and disable debug/actuator "
            "endpoints in production."
        ),
        evidence="\n".join(lines),
        route=f"GET /{hits[0]['path']}",
        request=f"GET /{hits[0]['path']}  (unauthenticated)",
        reproduction=(f"curl -s <base>/{hits[0]['path']} — it returns the real "
                      f"file contents ({hits[0]['label']})."),
        references=[REFS["A05"], REFS["api9"],
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Attack_Surface_Analysis_Cheat_Sheet.html"],
        tools=["nuclei", "feroxbuster", "gitdumper", "curl"],
    )


def _report_safe(ctx: Context) -> None:
    ctx.finding(
        id="a05-improper-inventory-safe",
        owasp="A05", severity="SAFE",
        title="No exposed .git/.env/backup/debug paths found",
        summary=(
            "Probed common sensitive paths (.git, .env, config, cloud "
            "credentials, SQL/SQLite dumps, /metrics, actuator, phpinfo) and none "
            "returned their signature contents. Note this is a fixed high-signal "
            "list, not exhaustive directory brute-forcing — run a wordlist scanner "
            "(feroxbuster/nuclei) for fuller coverage, and audit old/undocumented "
            "API versions separately."
        ),
        references=[REFS["A05"], REFS["api9"]],
    )
