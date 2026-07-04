"""SAST — static sink analysis of the source tree, chained to live DAST confirmation.

The DAST modules can only reach what they can authenticate to and trigger; a
vulnerability behind a role gate, in a hidden endpoint, or needing a privesc
chain stays invisible to them. When ``--source`` is given, this module reads the
code directly and flags high-signal, low-false-positive *sink* patterns:

  * command injection — ``os.system`` / ``subprocess(..., shell=True)`` on a
    non-literal (concatenated / f-string / variable) command,
  * SSRF — ``requests`` / ``httpx`` / ``urllib`` fetching a non-literal URL,
  * SSTI — ``Template(x)`` / ``.from_string(x)`` / ``render_template_string(x)``,
  * raw SQL — an f-string / ``%`` / ``+`` / ``.format`` built into ``.execute(``
    or ``text(`` (not a parameterised query),
  * code exec / unsafe deserialisation — ``eval`` / ``exec`` / ``pickle.loads`` /
    ``yaml.load`` (no SafeLoader) / ``marshal.loads`` on non-literals,
  * broken access control — a state-changing route with no auth ``Depends`` (or a
    commented-out one), and version disclosure via ``X-Powered-By`` / ``Server``.

**SAST→DAST chaining.** A static sink is a *lead*; on its own it can't tell
reachable-and-exploitable from dead code. So each sink is mapped back to the
route(s) that reach it (via a 0/1/2-hop call graph over the source), then a
class-specific live probe is fired against that route to *confirm* it:

  * CONFIRMED — the payload demonstrably fired (SSTI marker rendered, injected
    sleep delayed the response, a boolean SQL pair diverged, an unauth request
    was served) → the finding is elevated,
  * GATED — the route returns 401/403 for our principal: real sink, reachable
    only after privilege escalation (explains why black-box missed it),
  * otherwise the static sink stands as a lead to verify manually.

Precision over recall: taint checks fire only on *dynamic* arguments (never a
string literal); known-public routes and capability-token paths are suppressed;
decorator-level ``dependencies=[Depends(...)]`` auth is recognised.
"""

from __future__ import annotations

import ast
import os
import re
import time

from ..core.context import Context
from ..core.reqbuild import build_request, string_body_fields
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

_AUTH_HINTS = (
    "current_user", "current_active_user", "get_current", "rolesbasedauthchecker",
    "rolechecker", "require_", "has_permission", "has_role", "get_api_key",
    "oauth2_scheme", "verify_token", "verify_jwt", "authenticate", "auth_required",
    "get_user", "login_required", "permission", "authorizer",
)
_HTTP_FETCH_ROOTS = ("requests.", "httpx.", "aiohttp.")
_FETCH_VERBS = ("get", "post", "put", "delete", "head", "patch", "request", "options")

_PUBLIC_ROUTE = re.compile(
    r"login|logout|register|signup|sign-?up|/token|refresh|reset.?password|forgot|verif|"
    r"validate[_-]?(email|account)|activate|confirm|webhook|callback|oauth|/health|/docs|"
    r"openapi|\.well-known",
    re.IGNORECASE)
_CAP_TOKEN_PARAM = re.compile(r"\{[^}]*(token|code|secret|magic|invite|api[_-]?key)[^}]*\}",
                              re.IGNORECASE)
_COMMENTED_DEPENDS = re.compile(r"#[^\n]*\bDepends\s*\(\s*[A-Za-z_]")
_AUTH_WORD = re.compile(
    r"auth|role|permission|current[_ ]?user|require|oauth|jwt|api[_ ]?key|login|verif",
    re.IGNORECASE)
_HEADER_LEAK = re.compile(
    r"""\.headers\[\s*["'](X-Powered-By|Server|X-AspNet-Version|X-AspNetMvc-Version"""
    r"""|X-Runtime|X-Generator)["']\s*\]\s*=""", re.IGNORECASE)


# ── AST helpers ──────────────────────────────────────────────────────────────
def _callee(node: ast.Call) -> str:
    parts: list[str] = []
    f = node.func
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def _dynamic(n: ast.AST | None) -> bool:
    if n is None or isinstance(n, ast.Constant):
        return False
    return isinstance(n, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Attribute, ast.Call, ast.Subscript))


def _built_string(n: ast.AST | None) -> bool:
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


def _depends_is_auth(dep_call: ast.Call) -> bool:
    d = dep_call.args[0] if dep_call.args else None
    name = (d.id if isinstance(d, ast.Name) else
            _callee(d) if isinstance(d, ast.Call) else getattr(d, "attr", "")) if d else ""
    return _auth_ish(name)


def _handler_has_auth(fn: ast.AST) -> bool:
    args = getattr(fn, "args", None)
    if args is None:
        return False
    for sub in ast.walk(args):
        if isinstance(sub, ast.Call) and _callee(sub).split(".")[-1] == "Depends" and sub.args:
            if _depends_is_auth(sub):
                return True
    return False


def _decorator_deps_auth(dec: ast.AST) -> bool:
    if not isinstance(dec, ast.Call):
        return False
    deps = next((k.value for k in dec.keywords if k.arg == "dependencies"), None)
    if deps is None:
        return False
    for sub in ast.walk(deps):
        if isinstance(sub, ast.Call) and _callee(sub).split(".")[-1] == "Depends" and sub.args:
            if _depends_is_auth(sub):
                return True
    return False


def _route_decorator(dec: ast.AST):
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


def _scan_file(path: str, rel: str, lines: list[str], graph: dict) -> None:
    """Populate graph['sinks'|'handlers'|'calls'] from one file.

    graph['sinks']:   list of {kind, loc, code, func}
    graph['handlers']: func_name -> (method, path)
    graph['calls']:    func_name -> set(simple callee names)
    """
    try:
        tree = ast.parse("".join(lines), filename=path)
    except (SyntaxError, ValueError):
        return
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._parent = parent  # type: ignore[attr-defined]

    def enclosing_func(node) -> str | None:
        n = getattr(node, "_parent", None)
        while n is not None:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return n.name
            n = getattr(n, "_parent", None)
        return None

    sinks = graph["sinks"]
    handlers = graph["handlers"]
    calls = graph["calls"]

    def snippet(node) -> str:
        i = node.lineno - 1
        return lines[i].strip() if 0 <= i < len(lines) else ""

    def add(kind: str, node) -> None:
        sinks.append({"kind": kind, "loc": f"{rel}:{node.lineno}",
                      "code": snippet(node), "func": enclosing_func(node)})

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _callee(node)
            tail = name.split(".")[-1]
            a0 = _arg0(node)
            fn = enclosing_func(node)
            if fn:
                calls.setdefault(fn, set()).add(tail)

            if name in ("os.system", "os.popen") and _dynamic(a0):
                add("cmdi", node)
            elif tail in ("run", "call", "Popen", "check_output", "check_call") and (
                    name.startswith("subprocess.") or tail == "Popen"):
                shell = _kwarg(node, "shell")
                if isinstance(shell, ast.Constant) and shell.value is True and (
                        _dynamic(a0) or _built_string(a0)):
                    add("cmdi", node)
            elif (name.startswith(_HTTP_FETCH_ROOTS) or name in (
                    "urllib.request.urlopen", "urlopen")) and tail in _FETCH_VERBS + ("urlopen",):
                if isinstance(a0, (ast.Name, ast.BinOp, ast.JoinedStr, ast.Subscript)):
                    add("ssrf", node)
            elif tail in ("Template", "from_string", "render_template_string") and _dynamic(a0):
                add("ssti", node)
            elif tail in ("execute", "executemany", "executescript", "text", "raw") and _built_string(a0):
                add("sqli", node)
            elif name in ("eval", "exec") and _dynamic(a0):
                add("eval", node)
            elif name in ("pickle.loads", "cPickle.loads", "marshal.loads", "dill.loads",
                          "pickle.load") and _dynamic(a0):
                add("deser", node)
            elif name == "yaml.load":
                loader = _kwarg(node, "Loader")
                safe = loader is not None and "safe" in (
                    _callee(loader) if isinstance(loader, ast.Call) else
                    getattr(loader, "attr", getattr(loader, "id", ""))).lower()
                if not safe:
                    add("deser", node)

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                route = _route_decorator(dec)
                if not route:
                    continue
                handlers[node.name] = route
                if route[0] in ("post", "put", "patch", "delete"):
                    public = (_PUBLIC_ROUTE.search(route[1]) or _PUBLIC_ROUTE.search(node.name)
                              or _CAP_TOKEN_PARAM.search(route[1]))
                    if not (_handler_has_auth(node) or _decorator_deps_auth(dec)) and not public:
                        sinks.append({"kind": "noauth", "loc": f"{rel}:{node.lineno}",
                                      "code": f"{route[0].upper()} {route[1]}  ({node.name})",
                                      "func": node.name, "route": route})
                break

    for i, line in enumerate(lines, 1):
        if _COMMENTED_DEPENDS.search(line) and _AUTH_WORD.search(line):
            sinks.append({"kind": "commented_auth", "loc": f"{rel}:{i}",
                          "code": line.strip(), "func": None})
        if _HEADER_LEAK.search(line):
            sinks.append({"kind": "header_leak", "loc": f"{rel}:{i}",
                          "code": line.strip(), "func": None})


# ── call-graph route resolution ──────────────────────────────────────────────
def _reachable(handler: str, calls: dict, depth: int = 3) -> set:
    """Function names reachable from a handler within `depth` call hops."""
    seen, frontier = set(), {handler}
    for _ in range(depth):
        nxt = set()
        for f in frontier:
            for callee in calls.get(f, ()):  # callees are simple names
                if callee not in seen:
                    seen.add(callee)
                    nxt.add(callee)
        frontier = nxt
        if not frontier:
            break
    return seen


def _routes_for_sink(sink: dict, handlers: dict, calls: dict) -> list:
    """Candidate (method, path) routes whose handler reaches this sink's function."""
    if sink.get("route"):
        return [sink["route"]]
    func = sink.get("func")
    if not func:
        return []
    out = []
    for hname, route in handlers.items():
        if func == hname or func in _reachable(hname, calls):
            out.append(route)
    return out


# ── live confirmation probes ─────────────────────────────────────────────────
def _match_route(ctx: Context, method: str, path: str):
    m = method.upper()
    routes = [r for r in ctx.routes if r.method == m]
    for r in routes:
        if r.path == path:
            return r
    best = None
    for r in routes:                       # router-prefix: live path ends with decorator path
        if path not in ("?", "") and r.path.endswith(path):
            if best is None or len(r.path) < len(best.path):
                best = r
    return best


def _confirm_ssti(ctx: Context, r, token):
    payload, expect = "hh{{191*7}}hh", "hh1337hh"
    for p in (r.query_params or [])[:5]:
        nm = p.get("name")
        if not nm:
            continue
        try:
            resp = ctx.get(r.fill_path({}), token=token, params={nm: payload})
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code in (401, 403):
            return "GATED", f"{r.method} {r.path} -> {resp.status_code} (auth required)"
        if expect in (resp.text or ""):
            return "CONFIRMED", f"GET {r.path}?{nm}={{{{191*7}}}} rendered {expect}"
    if not ctx.safe and r.method in ("POST", "PUT", "PATCH"):
        sf = string_body_fields(r)
        if sf:
            path, body = build_request(ctx, r, token, overrides={f: payload for f in sf[:8]})
            try:
                resp = ctx.request(r.method, path, token=token, json=body)
                if expect in (resp.text or ""):
                    return "CONFIRMED", f"{r.method} {r.path} body rendered {expect}"
            except Exception:  # noqa: BLE001
                pass
    return "", ""


def _confirm_cmdi(ctx: Context, r, token):
    sleep_s, thresh = 3, 2.5
    payloads = [f"; sleep {sleep_s}", f"| sleep {sleep_s}", f"$(sleep {sleep_s})"]
    gated = False
    for p in (r.query_params or [])[:3]:
        nm = p.get("name")
        if not nm:
            continue
        try:
            base = ctx.get(r.fill_path({}), token=token, params={nm: "1"})
        except Exception:  # noqa: BLE001
            continue
        if base.status_code in (401, 403):
            gated = True
            continue
        for pay in payloads[:2]:
            try:
                t0 = time.monotonic()
                resp = ctx.get(r.fill_path({}), token=token, params={nm: "1" + pay})
                dt = time.monotonic() - t0
            except Exception:  # noqa: BLE001
                continue
            if resp.status_code in (401, 403):
                gated = True
                break
            if dt >= thresh:
                return "CONFIRMED", f"GET {r.path}?{nm}=…{pay!r} delayed {dt:.1f}s (injected sleep)"
    if gated:
        return "GATED", (f"{r.method} {r.path} returns 401/403 for the test principal — "
                         "reachable only with higher privilege (privesc chain)")
    return "", ""


def _confirm_sqli(ctx: Context, r, token):
    from .a03_injection import _SQLI_BOOL_PAIRS, _materially_differ
    for p in (r.query_params or [])[:3]:
        nm = p.get("name")
        if not nm:
            continue
        for t_pay, f_pay in _SQLI_BOOL_PAIRS[:2]:
            try:
                rt = ctx.get(r.fill_path({}), token=token, params={nm: t_pay})
                rf = ctx.get(r.fill_path({}), token=token, params={nm: f_pay})
            except Exception:  # noqa: BLE001
                break
            if rt.status_code in (401, 403):
                return "GATED", f"{r.method} {r.path} -> {rt.status_code} (auth required)"
            if _materially_differ(rt, rf):
                return "CONFIRMED", f"GET {r.path}?{nm}= boolean pair diverged ({len(rt.text)}B vs {len(rf.text)}B)"
    return "", ""


def _confirm_noauth(ctx: Context, r):
    if ctx.safe:
        return "", ""
    try:
        path, body = build_request(ctx, r, None)
        resp = ctx.request(r.method, path, json=body)  # NO credential
    except Exception:  # noqa: BLE001
        return "", ""
    if resp.status_code not in (401, 403, 404, 405):
        return "CONFIRMED", f"{r.method} {r.path} -> {resp.status_code} with no credential"
    return "", ""


_CONFIRMERS = {"ssti": _confirm_ssti, "cmdi": _confirm_cmdi, "sqli": _confirm_sqli}


def _chain(ctx: Context, kind: str, sinks: list, handlers: dict, calls: dict, token):
    """Return (verdict, evidence_line) — best confirmation across this kind's sinks."""
    best = ("", "")
    order = {"CONFIRMED": 3, "GATED": 2, "": 0}
    for sink in sinks[:8]:
        routes = ([sink["route"]] if kind == "noauth" else
                  _routes_for_sink(sink, handlers, calls))
        for (m, p) in routes[:4]:
            r = _match_route(ctx, m, p)
            if r is None:
                continue
            if kind == "noauth":
                v, ev = _confirm_noauth(ctx, r)
            else:
                v, ev = _CONFIRMERS[kind](ctx, r, token)
            if order.get(v, 0) > order.get(best[0], 0):
                best = (v, ev)
            if v == "CONFIRMED":
                return best
    return best


# kind -> (id, owasp, severity, title, summary, refs, tools)
_SPEC = {
    "cmdi": ("sast-command-injection", "A03", "CRITICAL", "OS command injection sink in source",
             "A shell command is executed with `shell=True` (or via os.system/popen) from a "
             "non-literal string — an attacker-influenced value reaches the shell → RCE. Use an "
             "argument list without a shell, or strictly validate input.",
             [REFS["A03"], _PS_CMDI], ["semgrep", "bandit", "CodeQL"]),
    "ssrf": ("sast-ssrf", "A10", "MEDIUM", "Server-side request to a non-literal URL (SSRF sink)",
             "An HTTP client fetches a non-constant URL — if any part is user-controlled the "
             "server can be made to reach internal services / cloud metadata. Allow-list the host.",
             [REFS["A10"], _PS_SSRF], ["semgrep", "bandit"]),
    "ssti": ("sast-ssti", "A03", "HIGH", "Server-side template injection sink in source",
             "User-influenceable input is compiled AS a template (Template/from_string/"
             "render_template_string) rather than passed as context — typically RCE.",
             [REFS["A03"], _PS_SSTI], ["tplmap", "semgrep"]),
    "sqli": ("sast-sql-raw", "A03", "HIGH", "Raw SQL built from an f-string / concatenation",
             "A SQL statement is assembled inline (f-string / `%` / `+` / .format) and handed to "
             "execute()/text() — SQL injection when any operand is input. Use bound parameters.",
             [REFS["ps-sqli"], REFS["A03"]], ["sqlmap", "semgrep", "bandit"]),
    "eval": ("sast-code-exec", "A03", "HIGH", "Dynamic code execution (eval/exec) on a non-literal",
             "eval()/exec() runs a non-constant string as code — direct RCE if any part is "
             "attacker-controlled. Remove it; dispatch explicitly instead.",
             [REFS["A03"]], ["bandit", "semgrep"]),
    "deser": ("sast-unsafe-deser", "A08", "HIGH", "Unsafe deserialisation of untrusted data",
              "pickle/marshal.loads or yaml.load without SafeLoader deserialises attacker data "
              "into live objects → RCE. Use JSON or yaml.safe_load.",
              [REFS["A08"]], ["bandit", "semgrep"]),
    "commented_auth": ("sast-auth-disabled", "A01", "HIGH",
                       "Authentication dependency commented out on an endpoint",
                       "An auth/role `Depends(...)` guard exists in the code but is commented out "
                       "— the endpoint ships without the access control its author intended.",
                       [REFS["A01"], REFS["cheat-authz"]], ["code review", "semgrep"]),
    "noauth": ("sast-route-no-auth", "A01", "MEDIUM",
               "State-changing route with no authentication dependency",
               "A POST/PUT/PATCH/DELETE handler declares no auth `Depends(...)`. If it mutates "
               "state it is reachable unauthenticated (broken access control).",
               [REFS["A01"], REFS["cheat-authz"]], ["code review"]),
    "header_leak": ("sast-version-disclosure", "A05", "LOW",
                    "Technology/version disclosed via a response header",
                    "An X-Powered-By / Server / X-Runtime header advertises the framework and "
                    "version, easing targeted exploitation. Strip it in middleware.",
                    [REFS["A05"]], ["curl -I", "nikto"]),
}
_ORDER = ["cmdi", "eval", "deser", "ssti", "sqli", "commented_auth", "ssrf", "noauth", "header_leak"]
_CONFIRMABLE = {"cmdi", "ssti", "sqli", "noauth"}
# When a sink is CONFIRMED live, elevate severity.
_ELEVATE = {"ssti": "CRITICAL", "sqli": "CRITICAL", "noauth": "HIGH", "cmdi": "CRITICAL"}


@module("sast", "Static Analysis + DAST chaining (source sinks)")
def run(ctx: Context) -> None:
    source_path = ctx.profile.source_path
    if not source_path or not os.path.isdir(source_path):
        ctx.note("no source path; static analysis skipped (black-box run)")
        return

    graph = {"sinks": [], "handlers": {}, "calls": {}}
    scanned = 0
    for path in _iter_py(source_path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        _scan_file(path, os.path.relpath(path, source_path), lines, graph)
        scanned += 1

    if not scanned:
        ctx.note("no Python source files found; static analysis skipped")
        return

    sinks, handlers, calls = graph["sinks"], graph["handlers"], graph["calls"]
    by_kind: dict[str, list] = {}
    for s in sinks:
        by_kind.setdefault(s["kind"], []).append(s)

    token = None
    p = ctx.principal("attacker", "user") or ctx.profile.any_authed()
    if p:
        token = p.token

    total = 0
    for kind in _ORDER:
        found = by_kind.get(kind)
        if not found:
            continue
        total += len(found)
        fid, owasp, sev, title, summary, refs, tools = _SPEC[kind]

        # de-dupe by loc
        seen, uniq = set(), []
        for s in found:
            if s["loc"] not in seen:
                seen.add(s["loc"])
                uniq.append(s)

        verdict, chain_ev = ("", "")
        if kind in _CONFIRMABLE:
            verdict, chain_ev = _chain(ctx, kind, uniq, handlers, calls, token)

        if verdict == "CONFIRMED":
            sev = _ELEVATE.get(kind, sev)
            title = f"CONFIRMED (live) — {title}"
        elif verdict == "GATED":
            title = f"{title} — reachable but role-gated"

        n = len(uniq)
        body = "\n".join(f"  {s['loc']}\n    {s['code'][:160]}" for s in uniq[:20])
        if chain_ev:
            tag = {"CONFIRMED": "LIVE-CONFIRMED", "GATED": "REACHABLE (gated)"}.get(verdict, "chain")
            body += f"\n\n  [{tag}] {chain_ev}"
        ctx.finding(
            id=fid, owasp=owasp, severity=sev,
            title=f"{title} ({n} sites)" if n > 1 else title,
            summary=summary + (
                "  LIVE-CONFIRMED against the running app via SAST→DAST chaining."
                if verdict == "CONFIRMED" else
                "  The sink is reachable but returns 401/403 for a low-privilege actor — "
                "exploitable after privilege escalation." if verdict == "GATED" else ""),
            evidence=body,
            location=uniq[0]["loc"],
            references=refs, tools=tools,
            reproduction=f"Review {uniq[0]['loc']}; " + (
                chain_ev if chain_ev else "confirm the argument is reachable from request input."),
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
        ctx.note(f"static analysis: {total} sink(s) across {scanned} file(s); "
                 f"{len(handlers)} route handlers indexed for chaining")
