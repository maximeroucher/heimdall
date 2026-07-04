"""SAST — lightweight static sink analysis of the target's source tree.

The DAST modules can only reach what they can authenticate to and trigger; a
vulnerability behind a role gate, in a hidden endpoint, or needing a privesc
chain stays invisible to them. When ``--source`` is given, this module reads the
code directly and flags high-signal, low-false-positive *sink* patterns — the
things a black-box scanner structurally can't see:

  * command injection — ``os.system`` / ``subprocess(..., shell=True)`` with a
    non-literal (concatenated / f-string / variable) command,
  * SSRF — ``requests`` / ``httpx`` / ``urllib`` fetching a non-literal URL,
  * SSTI — ``Template(x)`` / ``.from_string(x)`` / ``render_template_string(x)``,
  * raw SQL — an f-string / ``%`` / ``+`` / ``.format`` built into ``.execute(``
    or ``text(`` (not a parameterised query),
  * code exec / unsafe deserialisation — ``eval`` / ``exec`` / ``pickle.loads`` /
    ``yaml.load`` (no SafeLoader) / ``marshal.loads`` on non-literals,
  * broken access control — a state-changing route (POST/PUT/PATCH/DELETE) with
    no authentication ``Depends``, or an auth ``Depends`` that was commented out,
  * version disclosure — an explicit ``X-Powered-By`` / ``Server`` header.

Precision over recall: the taint heuristics only fire on *dynamic* arguments
(never a plain string literal), so parameterised queries and constant URLs don't
false-positive. Every hit carries its ``file:line`` — pair a SAST sink with a
DAST reachability probe for a confirmed finding.
"""

from __future__ import annotations

import ast
import os
import re

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "site-packages",
    "migrations", ".tox", "dist", "build", ".mypy_cache", ".pytest_cache", "tests",
}
_MAX_FILES = 3000
_PS_CMDI = "https://portswigger.net/web-security/os-command-injection"
_PS_SSRF = "https://portswigger.net/web-security/ssrf"
_PS_SSTI = "https://portswigger.net/web-security/server-side-template-injection"

# Names that make a Depends(...) an *authentication/authorisation* dependency.
_AUTH_HINTS = (
    "current_user", "current_active_user", "get_current", "rolesbasedauthchecker",
    "rolechecker", "require_", "has_permission", "has_role", "get_api_key",
    "oauth2_scheme", "verify_token", "verify_jwt", "authenticate", "auth_required",
    "get_user", "login_required", "permission",
)
_HTTP_FETCH_ROOTS = ("requests.", "httpx.", "aiohttp.")
_FETCH_VERBS = ("get", "post", "put", "delete", "head", "patch", "request", "options")

# Routes that are legitimately unauthenticated — never flag these as missing-auth
# (suppression to avoid false positives; it does NOT drive any positive finding).
_PUBLIC_ROUTE = re.compile(
    r"login|logout|register|signup|sign-?up|/token|refresh|reset.?password|forgot|verif|"
    r"validate[_-]?(email|account)|activate|confirm|webhook|callback|oauth|/health|/docs|"
    r"openapi|\.well-known",
    re.IGNORECASE)
# A capability token IN THE PATH (magic-link) is itself the credential — the route
# is authenticated by the unguessable token, so don't call it "missing auth".
_CAP_TOKEN_PARAM = re.compile(r"\{[^}]*(token|code|secret|magic|invite|api[_-]?key)[^}]*\}",
                              re.IGNORECASE)
# A commented-out auth guard: an actual commented Depends(<callable>) AND an auth word
# on the same line — not prose that merely mentions "Depends" (which self-FP'd).
_COMMENTED_DEPENDS = re.compile(r"#[^\n]*\bDepends\s*\(\s*[A-Za-z_]")
_AUTH_WORD = re.compile(
    r"auth|role|permission|current[_ ]?user|require|oauth|jwt|api[_ ]?key|login|verif",
    re.IGNORECASE)
_HEADER_LEAK = re.compile(
    r"""\.headers\[\s*["'](X-Powered-By|Server|X-AspNet-Version|X-AspNetMvc-Version"""
    r"""|X-Runtime|X-Generator)["']\s*\]\s*=""", re.IGNORECASE)


def _callee(node: ast.Call) -> str:
    """Dotted name of a call target: subprocess.run, os.system, requests.get, …"""
    parts: list[str] = []
    f = node.func
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def _dynamic(n: ast.AST | None) -> bool:
    """The argument is not a plain string/bytes literal — i.e. attacker-influenceable."""
    if n is None or isinstance(n, ast.Constant):
        return False
    return isinstance(n, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Attribute, ast.Call, ast.Subscript))


def _built_string(n: ast.AST | None) -> bool:
    """Argument is a string *constructed inline* — f-string, +/% concat, or .format()."""
    if isinstance(n, ast.JoinedStr):
        return True
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
        return True
    return False


def _kwarg(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _arg0(call: ast.Call):
    return call.args[0] if call.args else None


def _auth_ish(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in _AUTH_HINTS)


def _handler_has_auth(fn: ast.AST) -> bool:
    """Does any parameter's Depends(...) reference an auth dependency?"""
    args = getattr(fn, "args", None)
    if args is None:
        return False
    for sub in ast.walk(args):
        if isinstance(sub, ast.Call) and _callee(sub).split(".")[-1] == "Depends" and sub.args:
            dep = sub.args[0]
            depname = dep.id if isinstance(dep, ast.Name) else (
                _callee(dep) if isinstance(dep, ast.Call) else
                dep.attr if isinstance(dep, ast.Attribute) else "")
            if _auth_ish(depname):
                return True
    return False


def _decorator_deps_auth(dec: ast.AST) -> bool:
    """FastAPI routes can declare auth at the decorator level:
    ``@router.put(..., dependencies=[Depends(check_permissions)])``. Inspect that
    ``dependencies=`` list for an auth Depends (missing this false-positived
    c{api}tal's guarded PUT /{slug})."""
    if not isinstance(dec, ast.Call):
        return False
    deps = next((k.value for k in dec.keywords if k.arg == "dependencies"), None)
    if deps is None:
        return False
    for sub in ast.walk(deps):
        if isinstance(sub, ast.Call) and _callee(sub).split(".")[-1] == "Depends" and sub.args:
            d = sub.args[0]
            name = d.id if isinstance(d, ast.Name) else (
                _callee(d) if isinstance(d, ast.Call) else getattr(d, "attr", ""))
            if _auth_ish(name):
                return True
    return False


def _route_decorator(dec: ast.AST):
    """(method, path) if this decorator is @<x>.<verb>('/path'), else None."""
    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
        return None
    verb = dec.func.attr.lower()
    if verb not in ("get", "post", "put", "patch", "delete"):
        return None
    path = dec.args[0].value if (dec.args and isinstance(dec.args[0], ast.Constant)) else "?"
    return verb, path


def _iter_py(root: str):
    n = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS and not d.startswith(".")]
        for f in fn:
            if f.endswith(".py"):
                yield os.path.join(dp, f)
                n += 1
                if n >= _MAX_FILES:
                    return


def _scan_file(path: str, rel: str, lines: list[str], hits: dict) -> None:
    try:
        tree = ast.parse("".join(lines), filename=path)
    except (SyntaxError, ValueError):
        return

    def loc(node) -> str:
        return f"{rel}:{node.lineno}"

    def snippet(node) -> str:
        i = node.lineno - 1
        return lines[i].strip() if 0 <= i < len(lines) else ""

    def record(kind: str, node) -> None:
        hits.setdefault(kind, []).append((loc(node), snippet(node)))

    for node in ast.walk(tree):
        # ── call-sink checks ──────────────────────────────────────────────
        if isinstance(node, ast.Call):
            name = _callee(node)
            tail = name.split(".")[-1]
            a0 = _arg0(node)

            # command injection
            if name in ("os.system", "os.popen") and _dynamic(a0):
                record("cmdi", node)
            elif tail in ("run", "call", "Popen", "check_output", "check_call") and (
                    name.startswith("subprocess.") or tail == "Popen"):
                shell = _kwarg(node, "shell")
                shell_true = isinstance(shell, ast.Constant) and shell.value is True
                if shell_true and (_dynamic(a0) or _built_string(a0)):
                    record("cmdi", node)

            # SSRF: http client fetching a non-literal, non-constant URL
            elif (name.startswith(_HTTP_FETCH_ROOTS) or name in (
                    "urllib.request.urlopen", "urlopen")) and tail in _FETCH_VERBS + ("urlopen",):
                if isinstance(a0, (ast.Name, ast.BinOp, ast.JoinedStr, ast.Subscript)):
                    record("ssrf", node)

            # SSTI
            elif tail in ("Template", "from_string", "render_template_string") and _dynamic(a0):
                record("ssti", node)

            # raw SQL built inline
            elif tail in ("execute", "executemany", "executescript", "text", "raw") and _built_string(a0):
                record("sqli", node)

            # code execution
            elif name in ("eval", "exec") and _dynamic(a0):
                record("eval", node)

            # unsafe deserialisation
            elif name in ("pickle.loads", "cPickle.loads", "marshal.loads", "dill.loads",
                          "pickle.load") and _dynamic(a0):
                record("deser", node)
            elif name in ("yaml.load",):
                loader = _kwarg(node, "Loader")
                safe = loader is not None and "safe" in (
                    _callee(loader) if isinstance(loader, ast.Call) else
                    getattr(loader, "attr", getattr(loader, "id", ""))).lower()
                if not safe:
                    record("deser", node)

        # ── route-handler access control ──────────────────────────────────
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                route = _route_decorator(dec)
                if route and route[0] in ("post", "put", "patch", "delete"):
                    public = (_PUBLIC_ROUTE.search(route[1]) or _PUBLIC_ROUTE.search(node.name)
                              or _CAP_TOKEN_PARAM.search(route[1]))
                    has_auth = _handler_has_auth(node) or _decorator_deps_auth(dec)
                    if not has_auth and not public:
                        hits.setdefault("noauth", []).append(
                            (f"{rel}:{node.lineno}", f"{route[0].upper()} {route[1]}  ({node.name})"))
                    break

    # ── line-regex checks (comments aren't in the AST) ────────────────────
    for i, line in enumerate(lines, 1):
        if _COMMENTED_DEPENDS.search(line) and _AUTH_WORD.search(line):
            hits.setdefault("commented_auth", []).append((f"{rel}:{i}", line.strip()))
        if _HEADER_LEAK.search(line):
            hits.setdefault("header_leak", []).append((f"{rel}:{i}", line.strip()))


# kind -> (id, owasp, severity, title, one-liner, refs, tools)
_SPEC = {
    "cmdi": ("sast-command-injection", "A03", "CRITICAL",
             "OS command injection sink in source",
             "A shell command is executed with `shell=True` (or via os.system/popen) from a "
             "non-literal string — an attacker-influenced value reaches the shell → RCE. "
             "Use an argument list without a shell, or strictly validate/escape.",
             [REFS["A03"], _PS_CMDI], ["semgrep", "bandit", "CodeQL"]),
    "ssrf": ("sast-ssrf", "A10", "MEDIUM",
             "Server-side request to a non-literal URL (SSRF sink)",
             "An HTTP client fetches a URL that is not a constant — if any part is "
             "user-controlled the server can be made to reach internal services / cloud "
             "metadata. Allow-list the host and reject internal ranges.",
             [REFS["A10"], _PS_SSRF], ["semgrep", "bandit"]),
    "ssti": ("sast-ssti", "A03", "HIGH",
             "Server-side template injection sink in source",
             "User-influenceable input is compiled AS a template (Template/from_string/"
             "render_template_string) rather than passed as context — typically RCE. "
             "Never build templates from input; use logic-less templates + context vars.",
             [REFS["A03"], _PS_SSTI], ["tplmap", "semgrep"]),
    "sqli": ("sast-sql-raw", "A03", "HIGH",
             "Raw SQL built from an f-string / concatenation",
             "A SQL statement is assembled inline (f-string / `%` / `+` / .format) and handed "
             "to execute()/text() — classic SQL injection when any operand is input. Use bound "
             "parameters (execute(sql, params)) or the ORM.",
             [REFS["ps-sqli"], REFS["A03"]], ["sqlmap", "semgrep", "bandit"]),
    "eval": ("sast-code-exec", "A03", "HIGH",
             "Dynamic code execution (eval/exec) on a non-literal",
             "eval()/exec() runs a non-constant string as code — direct RCE if any part is "
             "attacker-controlled. Remove it; parse/dispatch explicitly instead.",
             [REFS["A03"]], ["bandit", "semgrep"]),
    "deser": ("sast-unsafe-deser", "A08", "HIGH",
              "Unsafe deserialisation of untrusted data",
              "pickle/marshal.loads or yaml.load without SafeLoader deserialises attacker data "
              "into live objects → RCE. Use safe formats (JSON) or yaml.safe_load.",
              [REFS["A08"]], ["bandit", "semgrep"]),
    "commented_auth": ("sast-auth-disabled", "A01", "HIGH",
                       "Authentication dependency commented out on an endpoint",
                       "An auth/role `Depends(...)` guard is present in the code but commented "
                       "out — the endpoint ships without the access control its author intended. "
                       "Re-enable the dependency (this is exactly how BFLA/BOLA slip in).",
                       [REFS["A01"], REFS["cheat-authz"]], ["code review", "semgrep"]),
    "noauth": ("sast-route-no-auth", "A01", "MEDIUM",
               "State-changing route with no authentication dependency",
               "A POST/PUT/PATCH/DELETE handler declares no auth `Depends(...)` — if it mutates "
               "server state it is reachable unauthenticated (broken access control). Confirm "
               "whether it is intentionally public; otherwise add an auth/role dependency.",
               [REFS["A01"], REFS["cheat-authz"]], ["code review"]),
    "header_leak": ("sast-version-disclosure", "A05", "LOW",
                    "Technology/version disclosed via a response header",
                    "An X-Powered-By / Server / X-Runtime header advertises the framework and "
                    "version, easing targeted exploitation. Strip it in a middleware.",
                    [REFS["A05"]], ["curl -I", "nikto"]),
}
# Emit order (most severe classes first).
_ORDER = ["cmdi", "eval", "deser", "ssti", "sqli", "commented_auth", "ssrf", "noauth", "header_leak"]


@module("sast", "Static Analysis (source sink scan)")
def run(ctx: Context) -> None:
    source_path = ctx.profile.source_path
    if not source_path or not os.path.isdir(source_path):
        ctx.note("no source path; static analysis skipped (black-box run)")
        return

    hits: dict[str, list] = {}
    scanned = 0
    for path in _iter_py(source_path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        rel = os.path.relpath(path, source_path)
        _scan_file(path, rel, lines, hits)
        scanned += 1

    if not scanned:
        ctx.note("no Python source files found; static analysis skipped")
        return

    total = 0
    for kind in _ORDER:
        found = hits.get(kind)
        if not found:
            continue
        total += len(found)
        fid, owasp, sev, title, summary, refs, tools = _SPEC[kind]
        # de-dupe identical (loc, code) pairs, keep order
        seen, uniq = set(), []
        for loc, code in found:
            if loc not in seen:
                seen.add(loc)
                uniq.append((loc, code))
        evidence = "\n".join(f"  {loc}\n    {code[:160]}" for loc, code in uniq[:20])
        n = len(uniq)
        ctx.finding(
            id=fid, owasp=owasp, severity=sev,
            title=f"{title} ({n} site{'s' if n != 1 else ''})" if n > 1 else title,
            summary=summary,
            evidence=evidence,
            location=uniq[0][0],
            references=refs,
            tools=tools,
            reproduction=f"Review {uniq[0][0]} — the flagged sink; confirm the argument is "
                         "reachable from request input, then exercise it dynamically.",
        )

    if total == 0:
        ctx.finding(
            id="sast-clean", owasp="A03", severity="SAFE",
            title="Static analysis found no dangerous sinks",
            summary=f"Scanned {scanned} Python file(s) for command/SQL/template injection, SSRF, "
                    "unsafe deserialisation, disabled/missing auth and version-header leaks; none "
                    "matched. (Absence of these patterns is not a proof of overall safety.)",
        )
    else:
        ctx.note(f"static analysis: {total} sink(s) across {scanned} file(s)")
