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
from ..core.reqbuild import build_request
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
    _write_bola(ctx)
    _self_escalation(ctx)


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
        # Positive control: a real admin SHOULD reach these routes. If it does,
        # the negative result is authoritative (routes are genuinely admin-gated,
        # not merely broken/unreachable for everyone).
        admin = _admin_principal(ctx)
        admin_ok = 0
        if admin:
            for r in admin_routes:
                try:
                    if ctx.get(r.path, token=admin.token).status_code < 300:
                        admin_ok += 1
                except Exception:  # noqa: BLE001
                    pass
        if admin and admin_ok:
            summary = (f"All {len(admin_routes)} admin-looking GET routes denied "
                       f"'{attacker.label}', while admin '{admin.label}' reached "
                       f"{admin_ok}/{len(admin_routes)} — authoritative: the routes are "
                       "admin-gated and enforce it.")
        elif admin:
            summary = (f"All {len(admin_routes)} admin-looking GET routes denied "
                       f"'{attacker.label}', but admin '{admin.label}' also could not reach "
                       "any — these routes may need higher privilege or aren't reachable; "
                       "result is not authoritative.")
        else:
            caveat = "" if trustworthy else (
                " NOTE: tested with a supplied principal of unverified privilege.")
            summary = (f"All {len(admin_routes)} admin-looking GET routes denied the token "
                       "(no admin principal available for a positive control)." + caveat)
        ctx.finding(
            id="a01-bfla-admin-routes",
            owasp="A01", severity="SAFE",
            title="Admin-scoped routes reject the tested low-privilege token",
            summary=summary,
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
            route=f"GET {hits[0][0].path}",
            request=(f"GET {hits[0][0].fill_path({hits[0][0].path_params[0]: victim.user_id})}\n"
                     f"Authorization: Bearer <{attacker.label} token>"),
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


def _admin_principal(ctx: Context):
    for role in ("admin", "super_admin", "superuser"):
        p = ctx.principal(role)
        if p and p.authed:
            return p
    return None


# ── Write-side BOLA: modify/delete another user's object ──────────────────────

_BOGUS_ID = "00000000-0000-0000-0000-0000000000ff"


def _write_bola(ctx: Context) -> None:
    """Cross-principal PATCH/PUT/DELETE: can attacker A mutate victim B's object?
    Higher impact than a read BOLA. Destructive, so FULL mode only. Uses B's
    known id; a non-403 where a bogus id is rejected shows the ownership check
    is missing on the write path.
    """
    if ctx.safe:
        ctx.note("safe mode: skipping cross-principal write (PATCH/DELETE) BOLA")
        return
    pair = _lowpriv_pair(ctx)
    if not pair:
        return
    attacker, victim = pair
    routes = [r for r in ctx.routes
              if r.method in ("PATCH", "PUT", "DELETE") and len(r.path_params) == 1
              and looks_like_id_param(r.path_params[0])]
    strong, weak = [], []
    for r in routes[:60]:
        pname = r.path_params[0]
        # A valid body (typed/FK-resolved) so PATCH/PUT reach the handler instead
        # of 422-ing on validation before the ownership check runs.
        body = None
        if r.method != "DELETE":
            _, body = build_request(ctx, r, attacker.token, principal=attacker)
        try:
            vic = ctx.request(r.method, r.fill_path({pname: victim.user_id}),
                              token=attacker.token, json=body)
            bog = ctx.request(r.method, r.fill_path({pname: _BOGUS_ID}),
                              token=attacker.token, json=body)
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"write-BOLA probe of {r.method} {r.path} errored: {exc}")
            continue
        if vic.status_code in (401, 403):
            continue  # properly denied
        # victim reached the handler while a bogus id is rejected as not-found.
        if bog.status_code in (401, 403, 404) and vic.status_code not in (404,):
            if vic.status_code < 300:
                strong.append((r, vic.status_code))
            else:
                weak.append((r, vic.status_code))
    if strong:
        sample = "\n".join(f"  {r.method} {r.path} [victim id] -> {c} (succeeded)"
                           for r, c in strong[:15])
        ctx.finding(
            id="a01-write-bola", owasp="A01", severity="HIGH",
            title=f"Write BOLA: low-priv user mutates other users' objects on "
                  f"{len(strong)} route(s)",
            summary=(
                f"As '{attacker.label}', Heimdall issued a PATCH/PUT/DELETE against "
                f"'{victim.label}''s object by id and it SUCCEEDED (2xx), while a bogus id is "
                "rejected — the write path performs no ownership check. An attacker can "
                "modify or delete other users' data."
            ),
            evidence=sample,
            route=f"{strong[0][0].method} {strong[0][0].path}",
            request=(f"{strong[0][0].method} "
                     f"{strong[0][0].fill_path({strong[0][0].path_params[0]: victim.user_id})}\n"
                     f"Authorization: Bearer <{attacker.label} token>"),
            reproduction=f"As user A, {strong[0][0].method} {strong[0][0].path} with user B's id.",
            references=[REFS["ps-idor"], REFS["A01"], REFS["cheat-authz"]],
            tools=["Burp Suite (Autorize)", "curl"],
        )
    elif weak:
        sample = "\n".join(f"  {r.method} {r.path} [victim id] -> {c} (reached handler)"
                           for r, c in weak[:15])
        ctx.finding(
            id="a01-write-bola", owasp="A01", severity="MEDIUM",
            title=f"Possible write BOLA on {len(weak)} route(s) (reached handler cross-user)",
            summary=(
                f"'{attacker.label}''s PATCH/PUT/DELETE on '{victim.label}''s object was not "
                "denied (no 401/403) — it reached handler logic and failed later (validation/"
                "conflict) rather than on ownership. Confirm with a valid body whether the "
                "mutation actually lands."
            ),
            evidence=sample,
            references=[REFS["ps-idor"], REFS["A01"]],
            tools=["Burp Suite (Autorize)", "curl"],
        )
    else:
        ctx.finding(
            id="a01-write-bola", owasp="A01", severity="SAFE",
            title="Write routes enforce ownership across users",
            summary=f"No user-keyed PATCH/PUT/DELETE let '{attacker.label}' operate on "
                    f"'{victim.label}''s object.",
        )


# ── Self privilege-escalation via mass assignment on a self-update route ───────

_PRIV_FIELDS = {
    "is_admin": True, "is_superuser": True, "is_super_admin": True, "admin": True,
    "is_staff": True, "is_moderator": True, "role": "admin", "roles": ["admin"],
    "scopes": "API", "scope": "API", "validated": True, "is_active": True,
    "is_verified": True, "verified": True, "account_type": "admin", "group": "admin",
}


def _reflects(obj, key, val) -> bool:
    if isinstance(obj, dict):
        if key in obj and _val_match(obj[key], val):
            return True
        return any(_reflects(v, key, val) for v in obj.values())
    if isinstance(obj, list):
        return any(_reflects(x, key, val) for x in obj)
    return False


def _val_match(got, want) -> bool:
    if isinstance(want, bool):
        return got is True
    if isinstance(want, list):
        return isinstance(got, list) and any(str(w).lower() in
               [str(g).lower() for g in got] for w in want)
    return str(got).lower() == str(want).lower()


def _self_escalation(ctx: Context) -> None:
    """Mass assignment on self: submit privileged fields to a self-update route
    (…/me PATCH/PUT) and confirm — by diffing a re-fetch — that a field flipped
    to our value. Catches 'user promotes self to admin / self-validates'.
    """
    if ctx.safe:
        ctx.note("safe mode: skipping self privilege-escalation probe")
        return
    princ = ctx.principal("attacker", "user")
    if not princ or not princ.authed:
        return
    routes = [r for r in ctx.routes
              if r.method in ("PATCH", "PUT") and not r.has_path_param
              and _is_self_scoped(r.path)]
    hits = []
    for r in routes[:30]:
        try:
            before = ctx.get(r.path, token=princ.token)
            before_json = before.json() if before.status_code < 300 else {}
            # only inject fields that aren't ALREADY at our target value
            payload = {k: v for k, v in _PRIV_FIELDS.items()
                       if not _reflects(before_json, k, v)}
            if not payload:
                continue
            resp = ctx.request(r.method, r.path, token=princ.token, json=payload)
            if resp.status_code >= 300:
                continue
            after = ctx.get(r.path, token=princ.token)
            after_json = after.json() if after.status_code < 300 else {}
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"self-escalation probe of {r.method} {r.path} errored: {exc}")
            continue
        stuck = [k for k, v in payload.items() if _reflects(after_json, k, v)]
        if stuck:
            hits.append((r, stuck))
    if hits:
        sample = "\n".join(f"  {r.method} {r.path} accepted privileged field(s): {stuck}"
                           for r, stuck in hits[:15])
        ctx.finding(
            id="a01-self-escalation", owasp="A01", severity="HIGH",
            title=f"Privilege escalation via self-update mass assignment on "
                  f"{len(hits)} route(s)",
            summary=(
                f"A low-privilege user ('{princ.label}') PATCHed its own record with "
                "privileged fields it should not control (e.g. is_admin / role / validated / "
                "account_type) and a re-fetch confirms the value CHANGED. The self-update "
                "endpoint mass-assigns attacker-controlled fields — direct privilege "
                "escalation."
            ),
            evidence=sample,
            reproduction=f"As a normal user, {hits[0][0].method} {hits[0][0].path} with "
                         f"{{{hits[0][1][0]!r}: <privileged value>}} in the body, then re-read.",
            references=[REFS["ps-massassign"], REFS["A01"], REFS["cheat-authz"]],
            tools=["Burp Suite", "curl"],
        )
    elif routes:
        ctx.finding(
            id="a01-self-escalation", owasp="A01", severity="SAFE",
            title="Self-update routes ignore injected privileged fields",
            summary=f"Injecting admin/role/validated fields into {len(routes)} self-update "
                    "route(s) did not change any privileged attribute (mass assignment blocked).",
        )
