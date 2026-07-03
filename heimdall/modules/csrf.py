"""CSRF on cookie/session-authenticated endpoints (A01).

Cross-Site Request Forgery only affects auth that the BROWSER sends
automatically — i.e. cookies. Bearer/API-key tokens aren't auto-attached, so
CSRF doesn't apply and this module reports N/A. For cookie-session apps it
checks the two server-side defences:

  * the session cookie's ``SameSite`` attribute (Lax/Strict blocks cross-site
    sends; ``None``/absent leaves it exposed), and
  * whether state-changing requests are accepted with the session cookie but
    WITHOUT a CSRF token / from a foreign ``Origin`` (no anti-CSRF token check).

Both weak ⇒ an attacker's page can drive authenticated state-changing requests.
"""

from __future__ import annotations

import re

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

_SAMESITE_RE = re.compile(r"samesite\s*=\s*(lax|strict|none)", re.I)
_SECURE_RE = re.compile(r"\bsecure\b", re.I)
_EVIL_ORIGIN = "https://evil.example.com"


@module("csrf", "Cross-Site Request Forgery")
def run(ctx: Context) -> None:
    if ctx.auth.auth_kind != "cookie":
        ctx.finding(
            id="a01-csrf-na", owasp="A01", severity="INFO",
            title="CSRF not applicable — token-based auth (not cookies)",
            summary=(
                f"Authentication is `{ctx.auth.auth_kind}` (sent explicitly via a header, "
                "not an ambient cookie), so a cross-site page cannot forge authenticated "
                "requests. CSRF checks apply only to cookie/session auth."
            ),
            references=[REFS["A01"]],
        )
        return

    setcookie = _login_setcookie(ctx)
    samesite = None
    if setcookie:
        m = _SAMESITE_RE.search(setcookie)
        samesite = m.group(1).lower() if m else None
    samesite_protected = samesite in ("lax", "strict")

    # Does the server accept state-changing requests without a CSRF token / from
    # a foreign Origin? A 403 there means an anti-CSRF check fired.
    princ = next((p for p in ctx.profile.principals.values()
                  if p.authed and p.token), None)
    accepted = []
    if princ:
        changers = [r for r in ctx.routes
                    if r.method in ("POST", "PUT", "PATCH", "DELETE")
                    and not _is_auth_route(r)][:20]
        for r in changers:
            try:
                resp = ctx.request(r.method, r.fill_path({p: "1" for p in r.path_params}),
                                   token=princ.token,
                                   headers={"Origin": _EVIL_ORIGIN}, json={})
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"CSRF probe {r.method} {r.path} failed: {exc}")
                continue
            if resp.status_code not in (401, 403):
                accepted.append(r)

    ss = samesite or "absent"
    if accepted and not samesite_protected:
        sample = "\n".join(f"  {r.method} {r.path}" for r in accepted[:12])
        ctx.finding(
            id="a01-csrf", owasp="A01", severity="HIGH",
            title="CSRF: session cookie lacks SameSite and no anti-CSRF token is enforced",
            summary=(
                f"The session cookie's SameSite is `{ss}` (so browsers send it on cross-site "
                f"requests) and {len(accepted)} state-changing endpoint(s) accepted a request "
                "carrying the cookie from a foreign Origin with no CSRF token. An attacker "
                "page can silently perform authenticated actions as the victim. Set "
                "`SameSite=Lax`/`Strict` on the session cookie AND require a per-session "
                "anti-CSRF token (or verify Origin) on state-changing requests."
            ),
            evidence=f"session cookie SameSite={ss}; accepted cross-origin without token:\n" + sample,
            reproduction="From an attacker origin, auto-submit a form/fetch with credentials "
                         "to one of the endpoints above; it succeeds using the victim's cookie.",
            references=[REFS["A01"], "https://portswigger.net/web-security/csrf"],
            tools=["Burp Suite (CSRF PoC generator)", "browser fetch({credentials:'include'})"],
        )
    elif samesite_protected:
        ctx.finding(
            id="a01-csrf", owasp="A01", severity="SAFE",
            title=f"Session cookie uses SameSite={ss} (baseline CSRF protection)",
            summary=(
                f"The session cookie is `SameSite={ss}`, so browsers withhold it on cross-site "
                "requests — the primary CSRF defence is in place. Still ensure state changes "
                "use POST (not GET) and add anti-CSRF tokens for defence-in-depth."
            ),
        )
    elif not accepted and princ:
        ctx.finding(
            id="a01-csrf", owasp="A01", severity="SAFE",
            title="State-changing requests are rejected cross-origin (anti-CSRF enforced)",
            summary="Cookie-authenticated state-changing endpoints rejected requests that "
                    "carried a foreign Origin and no CSRF token (401/403).",
        )
    else:
        ctx.note("CSRF: could not establish a cookie principal to test state changes")


def _is_auth_route(route) -> bool:
    blob = f"{route.path} {route.operation_id}".lower()
    return any(h in blob for h in ("login", "logout", "token", "register", "signin"))


def _login_setcookie(ctx: Context) -> str | None:
    ap = ctx.auth
    if not ap.login_path:
        return None
    cred = next((p for p in ctx.profile.principals.values() if p.password and p.email), None)
    if not cred:
        return None
    body = {ap.username_field: cred.email, ap.password_field: cred.password}
    try:
        if ap.login_style in ("form", "oauth_password"):
            if ap.login_style == "oauth_password":
                body["grant_type"] = "password"
            r = ctx.post(ap.login_path, data=body)
        else:
            r = ctx.post(ap.login_path, json=body)
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"CSRF SameSite probe login failed: {exc}")
        return None
    return r.headers.get("Set-Cookie")
