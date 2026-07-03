"""A01 — Broken Access Control.

Fully route-map driven, so it works on any FastAPI target:
  1. Auth enforcement: every route the OpenAPI doc marks as *secured* is called
     with NO token. A 2xx means the dependency isn't actually enforced.
  2. Function-level authz (BFLA): admin-looking routes are called with a
     low-privilege (attacker) token. A 2xx means missing role checks.
  3. IDOR probe: single-id GET routes are fetched with the attacker token at the
     victim's own id and at neighbouring ids, to spot missing object scoping.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import looks_like_id_param, module

_ADMIN_HINT = ("admin", "superuser", "super-admin", "internal", "manage", "/all",
               "make-admin", "make_admin", "impersonate", "sudo")
# Routes we must never call unauthenticated as a "should be blocked" test — they
# are legitimately public and would create noise.
_PUBLIC_OK = ("login", "register", "token", "openapi", "docs", "health",
              "reset", "forgot", "signup", "authorize", "/redoc")


def _is_public_by_design(path: str, oid: str) -> bool:
    blob = f"{path} {oid}".lower()
    return any(h in blob for h in _PUBLIC_OK)


@module("a01", "Broken Access Control / IDOR")
def run(ctx: Context) -> None:
    _unauth_enforcement(ctx)
    _bfla_admin(ctx)
    _idor(ctx)


def _unauth_enforcement(ctx: Context) -> None:
    """Secured GET routes must reject an unauthenticated caller."""
    secured_get = [r for r in ctx.routes.secured()
                   if r.method == "GET" and not r.has_path_param]
    broken = []
    for r in secured_get:
        if _is_public_by_design(r.path, r.operation_id):
            continue
        resp = ctx.get(r.path)  # no token
        if resp.status_code < 300:
            broken.append((r, resp))
    if broken:
        sample = "\n".join(f"  GET {r.path} -> {resp.status_code}" for r, resp in broken[:15])
        ctx.finding(
            id="a01-unauth-secured-routes",
            owasp="A01", severity="HIGH",
            title=f"{len(broken)} auth-required route(s) reachable without a token",
            summary=(
                "The OpenAPI document declares a security requirement on these routes, "
                "but the server returned a success status to an unauthenticated request. "
                "The auth dependency is declared but not enforced (or the route is public "
                "despite its schema), exposing data/actions to anonymous callers."
            ),
            evidence=sample,
            reproduction=f"curl -s {ctx.base_url}{broken[0][0].path}  # no Authorization header",
            references=[REFS["A01"], REFS["cheat-authz"]],
            tools=["Burp Suite (Authorize)", "ffuf", "curl"],
        )
    else:
        ctx.finding(
            id="a01-unauth-secured-routes",
            owasp="A01", severity="SAFE",
            title="Secured GET routes reject unauthenticated access",
            summary=f"All {len(secured_get)} auth-required no-path-param GET routes returned "
                    "an auth error to a token-less request.",
        )


def _bfla_admin(ctx: Context) -> None:
    """Admin-looking routes must reject a low-privilege token."""
    attacker = ctx.principal("attacker", "user")
    if not attacker or not attacker.authed:
        ctx.note("no low-privilege principal available; BFLA check skipped")
        return
    admin_routes = [
        r for r in ctx.routes
        if r.method == "GET" and not r.has_path_param
        and any(h in f"{r.path} {r.operation_id}".lower() for h in _ADMIN_HINT)
    ]
    leaked = []
    for r in admin_routes:
        resp = ctx.get(r.path, token=attacker.token)
        if resp.status_code < 300:
            leaked.append((r, resp))
    if leaked:
        sample = "\n".join(f"  GET {r.path} -> {resp.status_code}" for r, resp in leaked[:15])
        ctx.finding(
            id="a01-bfla-admin-routes",
            owasp="A01", severity="HIGH",
            title=f"{len(leaked)} admin-scoped route(s) accessible to a normal user",
            summary=(
                "Routes whose path/operation name implies administrative scope returned "
                "success to a freshly self-registered low-privilege account — a broken "
                "function-level authorization (BFLA) / privilege-escalation flaw."
            ),
            evidence=sample,
            reproduction=f"curl -s -H 'Authorization: Bearer <low-priv-token>' "
                         f"{ctx.base_url}{leaked[0][0].path}",
            references=[REFS["A01"], REFS["cheat-authz"]],
            tools=["Burp Suite (Authorize/AuthMatrix)", "curl"],
        )
    elif admin_routes:
        ctx.finding(
            id="a01-bfla-admin-routes",
            owasp="A01", severity="SAFE",
            title="Admin-scoped routes reject a low-privilege token",
            summary=f"All {len(admin_routes)} admin-looking GET routes denied the attacker token.",
        )


def _idor(ctx: Context) -> None:
    """Single-id GET routes: try the attacker's own id and neighbours."""
    attacker = ctx.principal("attacker", "user")
    if not attacker or not attacker.authed:
        return
    id_routes = [r for r in ctx.routes
                 if r.method == "GET" and len(r.path_params) == 1
                 and looks_like_id_param(r.path_params[0])]
    own = attacker.user_id
    hits = []
    for r in id_routes[:40]:
        pname = r.path_params[0]
        # probe values: attacker's own id (should work), and integer neighbours.
        probes = []
        if own:
            probes.append(own)
        probes += ["1", "2", "00000000-0000-0000-0000-000000000001"]
        got_own = False
        cross = None
        for val in probes:
            resp = ctx.get(r.fill_path({pname: val}), token=attacker.token)
            if val == own and resp.status_code < 300:
                got_own = True
            elif val != own and resp.status_code < 300 and len(resp.content) > 2:
                cross = (val, resp)
        if cross is not None:
            hits.append((r, cross))
    if hits:
        sample = "\n".join(
            f"  GET {r.path} [{r.path_params[0]}={val}] -> {resp.status_code} "
            f"({len(resp.content)}B)"
            for r, (val, resp) in hits[:15]
        )
        ctx.finding(
            id="a01-idor-object-access",
            owasp="A01", severity="MEDIUM",
            title=f"Possible IDOR on {len(hits)} object route(s)",
            summary=(
                "Object-by-id GET routes returned data for ids other than the attacker's "
                "own when queried with a low-privilege token. Confirm whether the returned "
                "objects belong to other tenants/users (true BOLA) vs. legitimately public "
                "reference data."
            ),
            evidence=sample,
            reproduction=f"Authenticate as a low-priv user, then GET "
                         f"{hits[0][0].path} with an id you do not own.",
            references=[REFS["ps-idor"], REFS["A01"]],
            tools=["Burp Suite (Intruder)", "Autorize", "curl"],
        )
