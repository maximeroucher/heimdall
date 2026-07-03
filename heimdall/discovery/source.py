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


def detect_db_url(source_path: str, secrets: list[Secret] | None = None) -> str | None:
    """The app's database connection string, from a source scan — so Heimdall can
    spawn a throwaway DB of the right kind (Postgres/MySQL/SQLite) automatically."""
    for s in (secrets if secrets is not None else scan_secrets(source_path)):
        if s.kind == "db_url" and "://" in s.value:
            return s.value.strip()
    return None


_CLIENTS_KEY = re.compile(r"^(auth_clients|oauth_clients|clients)\s*:\s*$", re.I)


def oauth_clients(source_path: str) -> list[dict]:
    """Best-effort extraction of registered OAuth clients (client_id + redirect
    URIs + optional secret) from a config's ``AUTH_CLIENTS`` / ``clients`` mapping,
    so the OIDC checks have a real client to drive ``/authorize`` with. Handles the
    common YAML shape without a YAML dependency (indentation-aware)."""
    root = Path(source_path)
    if not root.exists():
        return []
    out: list[dict] = []
    for fp in _iter_files(root, re.compile(r"\.ya?ml$")):
        try:
            out += _clients_from_yaml(fp.read_text(errors="ignore"))
        except OSError:
            continue
    seen, res = set(), []
    for c in out:
        if c["client_id"] and c["client_id"] not in seen:
            seen.add(c["client_id"])
            res.append(c)
    return res


def _clients_from_yaml(text: str) -> list[dict]:
    lines, out, i, n = text.splitlines(), [], 0, 0
    n = len(lines)
    while i < n:
        if not _CLIENTS_KEY.match(lines[i].strip()):
            i += 1
            continue
        block_indent = len(lines[i]) - len(lines[i].lstrip())
        i += 1
        child_indent, cur = None, None
        while i < n:
            ln = lines[i]
            if not ln.strip():
                i += 1
                continue
            ind = len(ln) - len(ln.lstrip())
            if ind <= block_indent:
                break
            if child_indent is None:
                child_indent = ind
            s = ln.strip()
            if ind == child_indent and s.endswith(":"):
                cur = {"client_id": s[:-1].strip().strip("\"'"),
                       "redirect_uris": [], "secret": None}
                out.append(cur)
            elif cur is not None and ind > child_indent:
                if s.startswith("- "):
                    cur["redirect_uris"].append(s[2:].strip().strip("\"'"))
                elif s.lower().startswith("secret:"):
                    cur["secret"] = s.split(":", 1)[1].strip().strip("\"'") or None
            i += 1
    return out


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


_DEV_MARKERS = re.compile(
    r"(?i)(debug\s*[:=]\s*true|\blocalhost\b|127\.0\.0\.1|host\.docker\.internal"
    r"|for (?:local )?development|for testing|example\.com|changeme|dummy)")


def dev_config_signal(source_path: str) -> str | None:
    """Heuristic: does the committed config look like a DEV / example config
    rather than production? If so, secrets/policies scanned from it (a committed
    key, a loose CORS setting) are dev artifacts — bad hygiene, but not proof of a
    production compromise — so config-derived findings should be caveated and not
    rated as if prod inherits them. Returns a short reason, or None.

    Signals: a ``*.template`` / ``*.example`` / ``*.sample`` sibling (implies the
    real config file is a local fill-in), and dev markers (debug=true, localhost,
    'for development', example.com) inside the config files."""
    root = Path(source_path)
    if not root.exists():
        return None
    reasons: list[str] = []
    tmpl = (list(root.glob("*.template.*")) + list(root.glob("*.template"))
            + list(root.glob("*.example*")) + list(root.glob("*.sample*"))
            + list(root.glob(".env.example")))
    if tmpl:
        reasons.append(f"a config template exists ({tmpl[0].name}) — the committed "
                       "config is a local/dev fill-in")
    hits = 0
    for i, fp in enumerate(_iter_files(root, _SECRET_FILES)):
        if i > 60:
            break
        try:
            text = fp.read_text(errors="ignore")
        except OSError:
            continue
        if _DEV_MARKERS.search(text):
            hits += 1
    if hits:
        reasons.append(f"dev markers (debug/localhost/example) in {hits} config file(s)")
    return "; ".join(reasons) if reasons else None


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


_ROUTE_DECORATOR = re.compile(
    r"""\.(get|post|put|patch|delete)\(\s*["']([^"'\n]+)["']""", re.I)


def index_routes(source_path: str) -> list[tuple[str, str, str]]:
    """Map route decorators to source. Returns [(METHOD, path, 'file:line'), …]
    by scanning FastAPI ``@router.post("/x")`` style decorators (multi-line ok)."""
    root = Path(source_path)
    if not root.exists():
        return []
    out: list[tuple[str, str, str]] = []
    for fp in _iter_files(root, re.compile(r"endpoints.*\.py$|routes?\.py$|.*_api\.py$|app\.py$")):
        try:
            text = fp.read_text(errors="ignore")
        except OSError:
            continue
        for m in _ROUTE_DECORATOR.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            method, path = m.group(1).upper(), m.group(2)
            out.append((method, path, f"{fp.relative_to(root)}:{line}"))
    return out


_WS_DECORATOR = re.compile(r"""\.websocket\(\s*["']([^"'\n]+)["']""", re.I)
_WS_ADD_ROUTE = re.compile(
    r"""\.add_(?:api_)?websocket_route\(\s*["']([^"'\n]+)["']""", re.I)
# router mounted with a prefix: include_router(x.router, prefix="/api")
_INCLUDE_PREFIX = re.compile(
    r"""include_router\([^)]*?prefix\s*=\s*["']([^"'\n]+)["']""", re.I | re.S)


def index_websocket_routes(source_path: str) -> list[tuple[str, str]]:
    """Find WebSocket endpoints — which OpenAPI never lists, so they're invisible
    to black-box discovery. Scans ``@app.websocket("/x")`` / ``@router.websocket``
    / ``add_websocket_route`` decorators. Returns [(path, 'file:line'), …].

    Router prefixes can't be resolved perfectly statically, so we return the
    decorator-declared path and, when the file mounts routers under a prefix, the
    prefixed variants too — the tester tries each and keeps whatever the server
    actually accepts."""
    root = Path(source_path)
    if not root.exists():
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for fp in _iter_files(root, re.compile(r"\.py$")):
        try:
            text = fp.read_text(errors="ignore")
        except OSError:
            continue
        if ".websocket(" not in text and "websocket_route" not in text:
            continue
        prefixes = [m.group(1) for m in _INCLUDE_PREFIX.finditer(text)]
        for pat in (_WS_DECORATOR, _WS_ADD_ROUTE):
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                loc = f"{fp.relative_to(root)}:{line}"
                for candidate in _ws_path_variants(m.group(1), prefixes):
                    if candidate not in seen:
                        seen.add(candidate)
                        out.append((candidate, loc))
    return out


def _ws_path_variants(path: str, prefixes: list[str]) -> list[str]:
    variants = [path]
    for pre in prefixes:
        combined = pre.rstrip("/") + "/" + path.lstrip("/")
        if combined not in variants:
            variants.append(combined)
    return variants


def locate_route(index: list[tuple[str, str, str]], method: str, path: str) -> str | None:
    """Find the source location for an (method, openapi-path). Exact match first,
    then a suffix match (routers mounted under a prefix)."""
    method = method.upper()
    for m, p, loc in index:
        if m == method and p == path:
            return loc
    for m, p, loc in index:
        if m == method and path.endswith(p) and p.count("/") >= 2:
            return loc
    return None


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
