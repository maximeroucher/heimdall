"""Optional white-box source scanning.

When Heimdall is pointed at the target's source tree (``--source``), it can:
  * locate the FastAPI app object / launch command (so it can boot the target),
  * harvest candidate signing secrets & config (enables offline JWT forging),
  * read the dependency stack (feeds the outdated-components check).

All of this is best-effort and read-only. Nothing here mutates the target repo.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..core.model import Secret

# Files worth scanning for secrets/config (kept small & high-signal).
_SECRET_FILES = re.compile(r"(\.env[\w.]*|.*\.ya?ml|.*config.*\.py|settings.*\.py|.*\.toml)$", re.I)
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
              "build", ".mypy_cache", ".pytest_cache", "migrations", ".ruff_cache"}

# key patterns -> secret kind
_SECRET_PATTERNS = [
    (re.compile(r"(?i)\b([A-Z0-9_]*SECRET[A-Z0-9_]*KEY[A-Z0-9_]*)\s*[:=]\s*['\"]?([^'\"\n#]+)"), "jwt_secret"),
    (re.compile(r"(?i)\b(SECRET_KEY|JWT_SECRET|TOKEN_SECRET|SIGNING_KEY)\s*[:=]\s*['\"]?([^'\"\n#]+)"), "jwt_secret"),
    (re.compile(r"(?i)\b(DATABASE_URL|SQLALCHEMY_DATABASE_URI)\s*[:=]\s*['\"]?([^'\"\n#]+)"), "db_url"),
    (re.compile(r"(?i)\b([A-Z0-9_]*API[_-]?KEY)\s*[:=]\s*['\"]?([^'\"\n#]+)"), "api_key"),
    (re.compile(r"(?i)\b(POSTGRES_PASSWORD|DB_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*['\"]?([^'\"\n#]+)"), "password"),
]

_PLACEHOLDER = re.compile(r"(?i)(change|placeholder|example|your[-_]|xxx|todo|<.*>|\$\{)")


def _iter_files(root: Path, want=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if want is None or want.search(fn):
                yield Path(dirpath) / fn


def scan_secrets(source_path: str, max_files: int = 400) -> list[Secret]:
    root = Path(source_path)
    if not root.exists():
        return []
    out: list[Secret] = []
    seen: set[tuple[str, str]] = set()
    for i, fp in enumerate(_iter_files(root, _SECRET_FILES)):
        if i > max_files:
            break
        try:
            text = fp.read_text(errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 500:
                continue
            for pat, kind in _SECRET_PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                name, value = m.group(1).strip(), m.group(2).strip().strip("'\"")
                if not value or len(value) < 4:
                    continue
                dedup = (name, value)
                if dedup in seen:
                    continue
                seen.add(dedup)
                out.append(Secret(
                    name=name, value=value,
                    source=f"{fp.relative_to(root)}:{lineno}", kind=kind,
                ))
        # Whole-file pass for PEM private keys — they live on one very long,
        # often \n-escaped line (e.g. the app's RSA_PRIVATE_PEM_STRING) that the
        # line scanner skips. A committed private key enables direct RS/ES token
        # forgery and RS→HS algorithm confusion.
        for pem in _find_private_keys(text):
            fp_key = pem[:60]
            if ("PRIVATE_KEY", fp_key) in seen:
                continue
            seen.add(("PRIVATE_KEY", fp_key))
            out.append(Secret(
                name="RSA_PRIVATE_KEY", value=pem,
                source=str(fp.relative_to(root)), kind="rsa_private_key",
            ))
    return out


_PRIVKEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.S,
)


def _find_private_keys(text: str) -> list[str]:
    # normalise \n-escaped single-line PEMs into real newlines before matching.
    normalised = text.replace("\\n", "\n")
    return [m.group(0) for m in _PRIVKEY_RE.finditer(normalised)]


def jwt_secret_candidates(secrets: list[Secret]) -> list[str]:
    """Ordered, de-duped list of plausible HS256 signing keys to try.

    Includes the literal values found AND a few transforms of placeholder-looking
    ones (a very common real weakness: shipping a derivative of the documented
    default), plus a short built-in weak-secret wordlist.
    """
    cands: list[str] = []
    for s in secrets:
        if s.kind == "jwt_secret" and s.value not in cands:
            cands.append(s.value)
    cands.extend([
        "secret", "changeme", "your-secret-key", "your-secret-key-change-in-production",
        "supersecret", "jwt-secret", "dev", "test", "password", "admin",
    ])
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.search(value))


# ── App-object / launch discovery ────────────────────────────────────────────

_APP_ASSIGN = re.compile(r"^\s*(\w+)\s*(?::\s*[\w\[\], .]+)?=\s*(?:FastAPI\(|get_application\(|create_app\()", re.M)


def find_app_target(source_path: str) -> str | None:
    """Guess the ``module.path:variable`` for uvicorn, e.g. ``app.main:app``.

    Prefers a ``main.py`` that assigns a module-level FastAPI()/factory result.
    """
    root = Path(source_path)
    if not root.exists():
        return None
    candidates = []
    for fp in _iter_files(root, re.compile(r"\.py$")):
        name = fp.name
        if name not in ("main.py", "app.py", "asgi.py", "server.py", "__init__.py"):
            continue
        try:
            text = fp.read_text(errors="ignore")
        except OSError:
            continue
        m = _APP_ASSIGN.search(text)
        if not m:
            continue
        var = m.group(1)
        rel = fp.relative_to(root).with_suffix("")
        mod = ".".join(rel.parts)
        # priority: main.py > app.py > others
        prio = {"main": 0, "app": 1, "asgi": 2, "server": 3}.get(fp.stem, 5)
        candidates.append((prio, f"{mod}:{var}"))
    candidates.sort()
    return candidates[0][1] if candidates else None


def read_stack(source_path: str) -> dict[str, str]:
    """Parse pinned dependency versions from requirements*.txt / pyproject.toml."""
    root = Path(source_path)
    stack: dict[str, str] = {}
    pat = re.compile(r"^\s*['\"]?([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|~=)\s*([0-9][\w.]*)")
    for fname in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        fp = root / fname
        if not fp.exists():
            continue
        try:
            for line in fp.read_text(errors="ignore").splitlines():
                m = pat.match(line)
                if m:
                    stack.setdefault(m.group(1).lower(), m.group(3))
        except OSError:
            continue
    return stack
