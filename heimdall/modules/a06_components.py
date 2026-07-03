"""A06 — Vulnerable & Outdated Components.

White-box only: it reads the target's pinned dependency stack off the source
tree (never the live target) and answers "is this app shipping components with
known CVEs?" in two complementary passes:
  1. pip-audit: if the tool is on PATH, run it against the requirements file and
     turn its JSON verdict into one consolidated finding (authoritative, keyed
     to the OSV/PyPI advisory database).
  2. Heuristic static checks: a small curated set of well-known risky pins
     (python-jose, old pyyaml/requests/fastapi/starlette) that we flag even when
     pip-audit is missing or clean, plus a stack summary for the report.

Everything here is best-effort: subprocess may be absent, time out, or emit
malformed JSON — each of those degrades to a ``ctx.note`` and the pass
continues. Without a source path there is nothing to audit, so we say so.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from ..core.context import Context
from ..core.taxonomy import REFS
from ..discovery.source import read_stack
from .base import module

# Security-sensitive packages we surface in the stack summary (auth, crypto,
# transport, templating — the ones whose version actually moves the risk needle).
_RELEVANT = (
    "fastapi", "starlette", "uvicorn", "sqlalchemy", "pydantic", "python-jose",
    "pyjwt", "passlib", "bcrypt", "cryptography", "requests", "authlib",
    "pyyaml", "jinja2", "python-multipart",
)

_PIP_AUDIT_TIMEOUT = 120  # seconds


def _version_tuple(v: str) -> tuple[int, ...]:
    """Parse a dotted version into an int tuple for ordered comparison.

    Best-effort: stops at the first non-numeric component (e.g. "2.32.0rc1" ->
    (2, 32, 0)), so it is only meaningful for the coarse ``< x.y`` gates below.
    """
    parts: list[int] = []
    for chunk in v.split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        if num == "":
            break
        parts.append(int(num))
    return tuple(parts)


@module("a06", "Vulnerable & Outdated Components")
def run(ctx: Context) -> None:
    source_path = ctx.profile.source_path
    if not source_path:
        ctx.note("no source path; component audit skipped (black-box)")
        ctx.finding(
            id="a06-no-source",
            owasp="A06", severity="INFO",
            title="Component audit needs the source tree or an SBOM",
            summary=(
                "Heimdall was run black-box (no --source), so the dependency stack is "
                "not visible from the outside. Vulnerable-and-outdated-components analysis "
                "requires the pinned requirements / lockfile or a generated SBOM "
                "(CycloneDX/SPDX). Re-run with the source tree, or feed an SBOM into "
                "pip-audit / Grype to enumerate known-vulnerable dependencies."
            ),
            references=[REFS["A06"]],
            tools=["pip-audit", "safety", "Grype", "Syft (SBOM)"],
        )
        return

    stack = read_stack(source_path)

    pip_audit_ran, pip_audit_vulns = _pip_audit(ctx, source_path)
    _heuristics(ctx, stack)
    _stack_summary(ctx, stack)

    # Only mark the class SAFE if pip-audit actually ran and came back clean; a
    # missing tool tells us nothing, so we stay silent rather than assert safety.
    if pip_audit_ran and not pip_audit_vulns:
        ctx.finding(
            id="a06-pip-audit-clean",
            owasp="A06", severity="SAFE",
            title="No known-vulnerable dependencies (pip-audit clean)",
            summary="pip-audit resolved the pinned stack against the advisory database "
                    "and reported zero known-vulnerable packages.",
        )


def _pip_audit(ctx: Context, source_path: str) -> tuple[bool, list[dict]]:
    """Run pip-audit if installed; return (did_run, list_of_vuln_records)."""
    if not shutil.which("pip-audit"):
        ctx.note("pip-audit not installed; falling back to heuristic component checks")
        return False, []

    req = os.path.join(source_path, "requirements.txt")
    if os.path.isfile(req):
        cmd = ["pip-audit", "-f", "json", "-r", req]
    else:
        cmd = ["pip-audit", "-f", "json"]

    try:
        proc = subprocess.run(
            cmd, cwd=source_path, capture_output=True, text=True,
            timeout=_PIP_AUDIT_TIMEOUT,
        )
    except FileNotFoundError:
        # Raced away between which() and run(), or PATH lied.
        ctx.note("pip-audit not runnable; falling back to heuristic component checks")
        return False, []
    except subprocess.TimeoutExpired:
        ctx.note(f"pip-audit timed out after {_PIP_AUDIT_TIMEOUT}s; skipping tool pass")
        return False, []
    except OSError as exc:
        ctx.note(f"pip-audit failed to start ({exc}); skipping tool pass")
        return False, []

    raw = proc.stdout.strip()
    if not raw:
        ctx.note("pip-audit produced no JSON output; skipping tool pass")
        return False, []

    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        ctx.note("pip-audit JSON was malformed; skipping tool pass")
        return False, []

    # pip-audit's schema shifted across versions: newer emits
    # {"dependencies": [...]}, older emits a bare list of dependency objects.
    if isinstance(data, dict):
        deps = data.get("dependencies", [])
    elif isinstance(data, list):
        deps = data
    else:
        ctx.note("pip-audit JSON had an unexpected shape; skipping tool pass")
        return False, []

    vulns: list[dict] = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name", "?")
        installed = dep.get("version", "?")
        for v in dep.get("vulns", []) or []:
            if not isinstance(v, dict):
                continue
            fixed = v.get("fix_versions") or []
            vulns.append({
                "name": name,
                "installed": installed,
                "id": v.get("id", "?"),
                "fixed": ", ".join(fixed) if fixed else "",
            })

    if not vulns:
        return True, []

    lines = []
    for v in vulns[:40]:
        fix = f" -> fixed in {v['fixed']}" if v["fixed"] else " (no fix released)"
        lines.append(f"  {v['name']} {v['installed']}  [{v['id']}]{fix}")
    has_fix = any(v["fixed"] for v in vulns)
    ctx.finding(
        id="a06-pip-audit-vulns",
        owasp="A06",
        severity="HIGH" if has_fix else "MEDIUM",
        title=f"pip-audit flagged {len(vulns)} known-vulnerable dependency record(s)",
        summary=(
            "pip-audit resolved the pinned dependency stack against the OSV/PyPI advisory "
            "database and matched packages carrying published CVE/GHSA/PYSEC advisories. "
            + ("A fixed release exists for at least one, so patching is a direct upgrade. "
               if has_fix else "No fixed release is available for some entries; assess "
               "exploitability and consider mitigations. ")
            + "Confirm which vulnerable code paths the app actually reaches before "
              "prioritising."
        ),
        evidence="\n".join(lines),
        reproduction=f"cd {source_path} && pip-audit -f json"
                     + ("  -r requirements.txt" if os.path.isfile(
                         os.path.join(source_path, "requirements.txt")) else ""),
        references=[REFS["A06"]],
        tools=["pip-audit", "safety", "Dependabot", "Grype"],
    )
    return True, vulns


def _heuristics(ctx: Context, stack: dict[str, str]) -> None:
    """Curated known-risky pins, flagged independently of pip-audit."""
    if "python-jose" in stack:
        ctx.finding(
            id="a06-python-jose",
            owasp="A06", severity="LOW",
            title=f"python-jose in use (version {stack['python-jose']})",
            summary=(
                "python-jose has a history of JWT algorithm-confusion and denial-of-service "
                "advisories (e.g. CVE-2024-33663 algorithm confusion with OpenSSH ECDSA keys, "
                "CVE-2024-33664 JWE decompression DoS). It is lightly maintained; PyJWT is the "
                "better-maintained, more widely audited alternative for JWT handling."
            ),
            evidence=f"python-jose=={stack['python-jose']}",
            reproduction="Review token verification code; migrate signing/verification to PyJWT "
                         "and pin an explicit allow-list of algorithms.",
            references=[REFS["A06"], REFS["ps-jwt"]],
            tools=["pip-audit", "PyJWT"],
        )

    def _older(pkg: str, floor: tuple[int, ...]) -> bool:
        v = stack.get(pkg)
        return bool(v) and _version_tuple(v) != () and _version_tuple(v) < floor

    if _older("pyyaml", (5, 4)):
        ctx.note(f"pyyaml=={stack['pyyaml']} < 5.4 — unsafe full_load default (CVE-2020-14343); "
                 "upgrade and use yaml.safe_load")
    if _older("requests", (2, 32)):
        ctx.note(f"requests=={stack['requests']} < 2.32 — cert-verification / Session handling "
                 "advisory (CVE-2024-35195); upgrade to >=2.32")
    if _older("fastapi", (0, 100)):
        ctx.note(f"fastapi=={stack['fastapi']} < 0.100 — well behind current; various fixes "
                 "since (incl. python-multipart hardening); plan an upgrade")
    if _older("starlette", (0, 36)):
        ctx.note(f"starlette=={stack['starlette']} < 0.36 — several security fixes landed since "
                 "(multipart DoS, etc.); plan an upgrade")


def _stack_summary(ctx: Context, stack: dict[str, str]) -> None:
    """Report the detected security-sensitive stack and CI hygiene advice."""
    detected = [(p, stack[p]) for p in _RELEVANT if p in stack]
    if detected:
        listing = "\n".join(f"  {p}=={v}" for p, v in detected)
    else:
        listing = ("  (no recognised security-sensitive packages resolved from "
                   "requirements*.txt / pyproject.toml)")
    ctx.finding(
        id="a06-stack-summary",
        owasp="A06", severity="INFO",
        title=f"Detected security-sensitive dependency stack ({len(detected)} package(s))",
        summary=(
            "Snapshot of the auth/crypto/transport/templating packages pinned in the source "
            "tree. Keep these current and gate merges on a dependency scan: wire pip-audit "
            "(or safety) into CI so a new advisory fails the build, and enable Dependabot / "
            "Renovate so upgrade PRs land automatically. Publish an SBOM (CycloneDX) so the "
            "stack can be re-audited against future advisories without the source tree."
        ),
        evidence=listing,
        reproduction="pip-audit  # in CI, plus Dependabot/Renovate for automated upgrades",
        references=[REFS["A06"]],
        tools=["pip-audit", "safety", "Dependabot", "Renovate", "Syft (SBOM)"],
    )
