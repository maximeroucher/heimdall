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


def _is_self_scoped(path: str) -> bool:
    """Routes that return the caller's OWN data (…/me, …/me/…) are not admin."""
    segs = path.lower().split("/")
    return "me" in segs or "myself" in segs or "current" in segs


@module("a01", "Broken Access Control / IDOR")
def run(ctx: Context) -> None:
    _unauth_enforcement(ctx)
    _bfla_admin(ctx)
    _idor(ctx)
    _cross_principal_bola(ctx)


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
    # A trustworthy negative needs a genuinely low-priv actor: the self-registered
    # attacker (role 'attacker', not supplied). A supplied 'user' credential may
    # secretly be over-privileged, which would turn a real BFLA into a false SAFE.
    # A genuine low-priv actor (self-registered attacker OR DB-provisioned user)
    # makes these results authoritative; only *supplied* creds are of unknown level.
    trustworthy = not attacker.supplied
    if not trustworthy:
        ctx.note(f"BFLA using supplied principal '{attacker.label}' of unverified "
                 "privilege — negatives are low-confidence")
    admin_routes = [
        r for r in ctx.routes
        if r.method == "GET" and not r.has_path_param
        and any(h in f"{r.path} {r.operation_id}".lower() for h in _ADMIN_HINT)
        and not _is_self_scoped(r.path)   # /users/me/... is caller-own, not admin
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
        caveat = "" if trustworthy else (
            f" NOTE: tested with the supplied principal '{attacker.label}', whose "
            "privilege level is unverified — re-run with a known low-privilege account "
            "to make this negative authoritative."
        )
        ctx.finding(
            id="a01-bfla-admin-routes",
            owasp="A01", severity="SAFE",
            title="Admin-scoped routes reject the tested low-privilege token",
            summary=f"All {len(admin_routes)} admin-looking GET routes denied the token." + caveat,
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


def _lowpriv_pair(ctx: Context):
    """Two distinct low-privilege principals that carry a known user id."""
    pool = [p for p in ctx.profile.principals.values()
            if p.authed and p.user_id and p.role in ("user", "attacker")]
    seen, uniq = set(), []
    for p in pool:
        if p.user_id not in seen:
            seen.add(p.user_id)
            uniq.append(p)
    return uniq[:2] if len(uniq) >= 2 else None


def _cross_principal_bola(ctx: Context) -> None:
    """True BOLA with real victims: using attacker A's token, fetch victim B's
    OWN object id on every single-id route. A 2xx where a bogus id is rejected
    proves A read an object it doesn't own — not reference data. This needs two
    provisioned low-priv principals with known ids (see self-provisioning).
    """
    pair = _lowpriv_pair(ctx)
    if not pair:
        ctx.note("cross-principal BOLA needs 2 known low-priv users "
                 "(provision with --provision 2); skipped")
        return
    attacker, victim = pair
    bogus = "00000000-0000-0000-0000-0000000000ff"
    id_routes = [r for r in ctx.routes
                 if r.method == "GET" and len(r.path_params) == 1
                 and looks_like_id_param(r.path_params[0])]
    hits = []
    for r in id_routes[:80]:
        pname = r.path_params[0]
        try:
            own = ctx.get(r.fill_path({pname: attacker.user_id}), token=attacker.token)
            if own.status_code >= 300:
                continue  # route isn't usable even for the owner; skip
            vic = ctx.get(r.fill_path({pname: victim.user_id}), token=attacker.token)
            bog = ctx.get(r.fill_path({pname: bogus}), token=attacker.token)
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"BOLA probe of {r.path} errored: {exc}")
            continue
        # A reads B's object (2xx) while a bogus id is rejected -> real BOLA.
        if vic.status_code < 300 and bog.status_code >= 400:
            hits.append((r, vic.status_code, len(vic.content)))
    if hits:
        sample = "\n".join(
            f"  GET {r.path} [victim id] -> {code} ({size}B); bogus id rejected"
            for r, code, size in hits[:20]
        )
        ctx.finding(
            id="a01-cross-principal-bola",
            owasp="A01", severity="HIGH",
            title=f"BOLA: low-priv user reads other users' objects on {len(hits)} route(s)",
            summary=(
                f"Authenticated as '{attacker.label}', Heimdall fetched objects belonging to "
                f"a different user ('{victim.label}') by id and received success, while the "
                "same route rejects a non-existent id — so the handler resolves and returns "
                "another user's object without an ownership check (true object-level "
                "authorization bypass). Empty bodies still count: the victim simply may hold "
                "no rows for that resource."
            ),
            evidence=sample,
            reproduction=(
                f"Log in as user A ({attacker.email}), then GET "
                f"{hits[0][0].path} substituting user B's id — returns 2xx instead of 403."
            ),
            references=[REFS["ps-idor"], REFS["A01"], REFS["cheat-authz"]],
            tools=["Burp Suite (Autorize)", "curl"],
        )
    else:
        ctx.finding(
            id="a01-cross-principal-bola",
            owasp="A01", severity="SAFE",
            title="Object-by-id routes enforce ownership across users",
            summary=f"Using two distinct low-priv accounts, no single-id GET route let "
                    f"'{attacker.label}' read '{victim.label}''s objects while rejecting bogus ids.",
        )
