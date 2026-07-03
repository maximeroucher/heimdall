"""Session / token lifecycle (A07): expiry, refresh rotation, logout revocation.

Stateless bearer tokens are only as safe as their lifecycle. This module logs in
fresh (bypassing any Heimdall-minted token) to inspect the *real* token, then:
  * checks the access token actually carries a bounded ``exp``;
  * exercises the refresh endpoint to see whether refresh tokens ROTATE (an old
    refresh token must stop working after it is used once);
  * checks whether logging out actually revokes the token server-side.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.taxonomy import REFS
from ..discovery.auth import decode_jwt
from .base import module

_REFRESH_FIELDS = ("refresh_token", "refreshToken", "refresh")


def _fresh_login(ctx: Context):
    """Log in a principal that has a password; return (access, refresh, raw_json)."""
    ap = ctx.auth
    if not ap.login_path:
        return None, None, None
    cred = next((p for p in ctx.profile.principals.values() if p.password and p.email), None)
    if not cred:
        return None, None, None
    body = {ap.username_field: cred.email, ap.password_field: cred.password}
    try:
        if ap.login_style in ("form", "oauth_password"):
            if ap.login_style == "oauth_password":
                body["grant_type"] = "password"
                if ap.scopes_field:
                    body[ap.scopes_field] = "API"
            r = ctx.post(ap.login_path, data=body)
        else:
            r = ctx.post(ap.login_path, json=body)
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"lifecycle fresh-login failed: {exc}")
        return None, None, None
    if r.status_code != 200:
        return None, None, None
    try:
        j = r.json()
    except ValueError:
        return None, None, None
    access = j.get("access_token") or j.get("token")
    refresh = next((j[f] for f in _REFRESH_FIELDS if j.get(f)), None)
    return access, refresh, j


@module("session", "Session / token lifecycle")
def run(ctx: Context) -> None:
    access, refresh, _ = _fresh_login(ctx)
    _token_expiry(ctx, access)
    _refresh_rotation(ctx, refresh)
    _logout_invalidation(ctx, access)


def _token_expiry(ctx: Context, access: str | None) -> None:
    if not access:
        ctx.note("no fresh access token; expiry check skipped")
        return
    decoded = decode_jwt(access)
    if decoded is None:
        ctx.note("access token is opaque (not a JWT); expiry not inspectable here")
        return
    claims = decoded[1]
    exp = claims.get("exp")
    iat = claims.get("iat") or claims.get("nbf")
    if exp is None:
        ctx.finding(
            id="session-no-exp", owasp="A07", severity="HIGH",
            title="Access token has no expiry (`exp`) — tokens never expire",
            summary=(
                "The access token carries no `exp` claim, so a stolen token is valid forever. "
                "Combined with no server-side revocation, one leaked token is a permanent "
                "credential. Add a short `exp` and refresh-token rotation."
            ),
            evidence=f"claims present: {sorted(claims)} (no exp)",
            references=[REFS["A07"]],
            tools=["jwt_tool", "Burp"],
        )
        return
    if iat and isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        hours = (exp - iat) / 3600.0
        if hours > 24:
            ctx.finding(
                id="session-long-exp", owasp="A07", severity="MEDIUM",
                title=f"Very long access-token lifetime (~{hours:.0f}h)",
                summary=(
                    f"The access token is valid for ~{hours:.0f} hours. Long-lived bearer "
                    "tokens widen the window for a stolen token; prefer short access tokens "
                    "(minutes) plus rotating refresh tokens."
                ),
                evidence=f"exp - iat = {int(exp - iat)}s (~{hours:.1f}h)",
                references=[REFS["A07"]],
                tools=["jwt_tool"],
            )
            return
    ctx.finding(
        id="session-exp", owasp="A07", severity="SAFE",
        title="Access token carries a bounded expiry",
        summary="The access token has an `exp` claim within a reasonable window.",
    )


def _find_refresh_route(ctx: Context):
    for r in ctx.routes.by_method("POST"):
        blob = f"{r.path} {r.operation_id}".lower()
        if "refresh" in blob:
            return r
    # OAuth token endpoint that takes grant_type=refresh_token
    from ..discovery.openapi import body_field_names
    for r in ctx.routes.by_method("POST"):
        if "token" in r.path.lower():
            fields = [f.lower() for f in body_field_names(r)]
            if any(f in fields for f in _REFRESH_FIELDS) or "grant_type" in fields:
                return r
    return None


def _do_refresh(ctx: Context, route, refresh: str):
    """POST a refresh; return (response, new_refresh_or_None)."""
    ap = ctx.auth
    forms = ap.login_style in ("form", "oauth_password")
    body = {"refresh_token": refresh, "grant_type": "refresh_token"} if forms \
        else {"refresh_token": refresh}
    try:
        r = ctx.post(route.path, data=body) if forms else ctx.post(route.path, json=body)
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"refresh call failed: {exc}")
        return None, None
    new = None
    if r.status_code == 200:
        try:
            j = r.json()
            new = next((j[f] for f in _REFRESH_FIELDS if j.get(f)), None)
        except ValueError:
            pass
    return r, new


def _refresh_rotation(ctx: Context, refresh: str | None) -> None:
    if not refresh:
        ctx.note("no refresh token issued at login; rotation check skipped")
        return
    route = _find_refresh_route(ctx)
    if route is None:
        ctx.note("no refresh endpoint discovered; rotation check skipped")
        return
    # First refresh: consume the token, expect a NEW refresh token back.
    r1, new_refresh = _do_refresh(ctx, route, refresh)
    if r1 is None or r1.status_code != 200:
        ctx.note(f"initial refresh did not succeed (HTTP {getattr(r1,'status_code','?')}); "
                 "rotation check inconclusive")
        return
    if not new_refresh or new_refresh == refresh:
        ctx.finding(
            id="session-refresh-static", owasp="A07", severity="MEDIUM",
            title="Refresh token does not rotate on use",
            summary=(
                "Using the refresh token did not return a new one (the same token stays "
                "valid). Static refresh tokens can't detect theft/replay — a stolen refresh "
                "token grants indefinite access. Rotate on every use and revoke the family on "
                "reuse."
            ),
            evidence=f"refresh at {route.path} returned no new/changed refresh token",
            references=[REFS["A07"]],
            tools=["Burp Repeater"],
        )
        return
    # Rotation happened — now REUSE the original (already-consumed) refresh token.
    r2, _ = _do_refresh(ctx, route, refresh)
    if r2 is not None and r2.status_code == 200:
        ctx.finding(
            id="session-refresh-reuse", owasp="A07", severity="HIGH",
            title="Consumed refresh token is still accepted (no reuse detection)",
            summary=(
                "After the refresh token rotated, the ORIGINAL (already-used) refresh token "
                "was accepted again. Without single-use enforcement + family revocation, a "
                "stolen refresh token can be replayed even after the legitimate user rotates."
            ),
            evidence=f"reusing the consumed refresh token at {route.path} -> "
                     f"HTTP {r2.status_code}",
            references=[REFS["A07"]],
            tools=["Burp Repeater"],
        )
        return
    ctx.finding(
        id="session-refresh-rotation", owasp="A07", severity="SAFE",
        title="Refresh tokens rotate and reuse is rejected",
        summary="The refresh token rotated on use and the consumed token was rejected on "
                "replay — single-use rotation is enforced.",
    )


def _logout_invalidation(ctx: Context, access: str | None) -> None:
    if not ctx.auth.logout_path:
        ctx.note("no logout endpoint discovered; revocation check skipped")
        return
    if not access:
        return
    # A route the fresh access token is authorized on, to test validity pre/post.
    probe = ctx.auth.me_path
    if not probe:
        ctx.note("no 'me' route to verify token validity around logout; check skipped")
        return
    try:
        before = ctx.get(probe, token=access)
        if before.status_code >= 300:
            ctx.note(f"fresh token not accepted at {probe} (HTTP {before.status_code}); "
                     "logout-revocation check inconclusive (token likely scope-limited)")
            return
        ctx.post(ctx.auth.logout_path, token=access)
        after = ctx.get(probe, token=access)
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"logout-revocation probe failed: {exc}")
        return
    if after.status_code < 300:
        ctx.finding(
            id="session-logout-no-revoke", owasp="A07", severity="MEDIUM",
            title="Bearer token remains valid after logout (no server-side revocation)",
            summary=(
                "After calling the logout endpoint, the same access token still authorized a "
                "protected request. Stateless tokens without a revocation list stay usable "
                "until expiry, so a logged-out (or stolen) token keeps working. Add a jti "
                "denylist / short expiry."
            ),
            evidence=f"{probe} returned {before.status_code} before logout and "
                     f"{after.status_code} after — token not revoked",
            references=[REFS["A07"]],
            tools=["Burp Repeater"],
        )
    else:
        ctx.finding(
            id="session-logout-revoke", owasp="A07", severity="SAFE",
            title="Logout revokes the token server-side",
            summary=f"The access token was rejected at {probe} after logout.",
        )
