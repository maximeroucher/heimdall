"""A01 / OIDC — OAuth 2 / OpenID Connect flow security.

Only applies to an app that IS an OAuth/OIDC provider — so the module first finds
one, two hint-free ways, and cleanly no-ops otherwise:

  * the standard discovery doc at ``/.well-known/openid-configuration`` (or
    ``/oauth-authorization-server``), which self-describes every endpoint and
    capability; or
  * an authorization endpoint identified by its OAuth PROTOCOL parameters — a
    route that takes ``response_type`` AND ``redirect_uri`` (RFC 6749 defines
    those names, so this is protocol identification, not vuln-name guessing).

Checks:
  1. Discovery-doc hygiene (when a well-known doc exists): implicit/hybrid flow
     advertised, PKCE not offered (no S256), ``none`` client-auth, ROPC grant,
     non-HTTPS issuer.
  2. redirect_uri strictness — the flagship, and the source of the worst OIDC
     bugs (authorization-code theft). Drive ``/authorize`` with a *registered*
     client but an ATTACKER ``redirect_uri``; if the endpoint redirects to /
     targets the attacker host instead of rejecting it, code theft is possible.

Deeper flow abuses (PKCE *enforcement*, ``state``/``nonce`` validation,
auth-code single-use + client-binding, confidential-client auth) need a full
scripted login+consent flow and are flagged for manual follow-up, not guessed.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

_WELL_KNOWN = ("/.well-known/openid-configuration",
               "/.well-known/oauth-authorization-server")
_ATTACKER_HOST = "evil-heimdall-oidc.test"
_ATTACKER_REDIRECT = f"https://{_ATTACKER_HOST}/callback"


@module("oidc", "OAuth / OIDC Flow Security")
def run(ctx: Context) -> None:
    wk = _fetch_well_known(ctx)
    authz = _find_authorize(ctx)
    if not wk and not authz:
        ctx.note("oidc: no OIDC discovery doc and no OAuth authorize endpoint — "
                 "not an OAuth/OIDC provider")
        return

    made = False
    if wk:
        made |= _check_well_known(ctx, wk)
    if authz:
        made |= _check_redirect_strictness(ctx, authz)
    if not made:
        ctx.note("oidc: OAuth/OIDC surface present; no config/redirect issues found")


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery ────────────────────────────────────────────────────────────────

def _fetch_well_known(ctx: Context) -> dict | None:
    for p in _WELL_KNOWN:
        try:
            r = ctx.get(p, timeout=8, retry_429=False)
        except requests.RequestException:
            continue
        if r.status_code == 200 and "json" in r.headers.get("Content-Type", "").lower():
            try:
                d = r.json()
            except Exception:  # noqa: BLE001
                continue
            if isinstance(d, dict) and ("authorization_endpoint" in d or "issuer" in d):
                return d
    return None


def _find_authorize(ctx: Context):
    """A route that takes the OAuth authorize params response_type + redirect_uri."""
    for r in ctx.routes:
        names = {p.get("name", "").lower() for p in r.query_params if isinstance(p, dict)}
        names |= {f.lower() for f in body_field_names(r)}
        if "response_type" in names and "redirect_uri" in names:
            return r
    return None


# ── Tier 1: discovery-doc hygiene ────────────────────────────────────────────

def _check_well_known(ctx: Context, wk: dict) -> bool:
    issues = []
    rts = [str(x).lower() for x in wk.get("response_types_supported", [])]
    if any("token" in rt for rt in rts):   # 'token' or 'id_token token' = implicit/hybrid
        issues.append(("MEDIUM", "implicit/hybrid flow advertised (response_types "
                       f"include {[rt for rt in rts if 'token' in rt]}) — tokens in "
                       "the URL fragment leak via history/referrer; use code+PKCE"))
    pkce = [str(x).upper() for x in wk.get("code_challenge_methods_supported", [])]
    if not pkce or "S256" not in pkce:
        # Not *advertised* isn't proof it's not *supported/enforced* (that needs a
        # flow test) — so this is a discovery-completeness gap, LOW.
        issues.append(("LOW", "PKCE S256 not advertised "
                       f"(code_challenge_methods_supported={pkce or 'absent'}) — "
                       "discovery-driven public clients won't use PKCE; advertise "
                       "S256 and verify it is enforced"))
    auth_methods = [str(x).lower() for x in
                    wk.get("token_endpoint_auth_methods_supported", [])]
    if "none" in auth_methods:
        issues.append(("LOW", "token endpoint allows client auth 'none' — public "
                       "clients accepted; ensure they're PKCE-bound and can't act "
                       "as confidential clients"))
    grants = [str(x).lower() for x in wk.get("grant_types_supported", [])]
    if "password" in grants:
        issues.append(("LOW", "ROPC 'password' grant supported — discouraged "
                       "(ships the user's password through the client)"))
    issuer = str(wk.get("issuer", ""))
    ihost = (urlparse(issuer).hostname or "").lower()
    local = ihost in ("localhost", "127.0.0.1", "::1") or ihost.endswith((".local", ".test"))
    if issuer.startswith("http://") and not local:
        issues.append(("LOW", f"issuer is not HTTPS ({issuer})"))
    if not issues:
        return False
    worst = "MEDIUM" if any(s == "MEDIUM" for s, _ in issues) else "LOW"
    ctx.finding(
        id="oidc-weak-discovery", owasp="A01", severity=worst,
        title=f"OIDC discovery advertises weak settings ({len(issues)})",
        summary=(
            "The OpenID Connect discovery document advertises configuration that "
            "weakens the protocol's guarantees: "
            + "; ".join(m for _s, m in issues) + ". Prefer authorization-code + "
            "PKCE (S256) for all clients, drop the implicit/hybrid and ROPC grants, "
            "and require client authentication for confidential clients."
        ),
        evidence="\n".join(f"  [{s}] {m}" for s, m in issues),
        route="GET /.well-known/openid-configuration",
        references=[REFS["A01"], "https://portswigger.net/web-security/oauth",
                    "https://openid.net/specs/openid-connect-discovery-1_0.html"],
        tools=["Burp Suite", "curl"],
    )
    return True


# ── Tier 2: redirect_uri strictness ──────────────────────────────────────────

def _fire_authorize(ctx: Context, route, params, token):
    path = route.fill_path({p: "1" for p in route.path_params})
    body_fields = {f.lower() for f in body_field_names(route)}
    kw = {"token": token, "timeout": 10, "retry_429": False, "allow_redirects": False}
    try:
        if "response_type" in body_fields and route.method != "GET":
            return ctx.request(route.method, path, data=params, **kw)
        return ctx.get(path, params=params, **kw)
    except requests.RequestException:
        return None


def _redirect_accepted(resp, host: str) -> str | None:
    """Did the endpoint actually REDIRECT the browser to the attacker host?

    Deliberately strict to avoid the classic false positive: the GET authorize
    page legitimately renders a LOGIN FORM that echoes redirect_uri into a hidden
    field (to carry it through login) — validation happens when that form is
    submitted, so a form-field echo is NOT code theft. We only flag an *actual*
    redirect: a 3xx Location to the attacker host, or a genuine client-side
    redirect construct (meta-refresh / window.location) pointing there — not a
    param echoed into form markup, and never an error response echoing it back."""
    if resp is None:
        return None
    # The attacker host must be the Location's actual HOST (the redirect target),
    # not merely present in the URL. A 302 to the app's OWN login page that
    # *carries* redirect_uri as a query param (…/login?redirect_uri=attacker) is
    # NOT code theft — the app validates it when that login form is submitted.
    if 300 <= resp.status_code < 400:
        loc = resp.headers.get("Location", "")
        target = loc if "//" in loc else "//" + loc            # tolerate scheme-relative
        if (urlparse(target).hostname or "").lower() == host.lower():
            return f"HTTP {resp.status_code} Location host is the attacker: {loc[:150]}"
        return None
    if resp.status_code < 400:            # only a non-error response can *use* it
        try:
            body = resp.text or ""
        except Exception:  # noqa: BLE001
            body = ""
        low = body.lower()
        # a real client-side redirect construct pointing AT the attacker host —
        # not a param echoed into a hidden form input.
        for pat in ("window.location", "location.href", "location.replace",
                    'http-equiv="refresh"'):
            idx = low.find(pat)
            if idx != -1 and host in body[idx:idx + 200]:
                return f"client-side redirect to attacker host via {pat}"
    return None


_FALLBACK_CLIENTS = ["client", "web", "app", "frontend", "spa", "oidc"]


def _check_redirect_strictness(ctx: Context, authz) -> bool:
    from ..discovery.source import oauth_clients
    src = oauth_clients(ctx.profile.source_path) if ctx.profile.source_path else []
    # Prefer real registered clients from config (a strict result is then
    # meaningful); otherwise fall back to generic ids so the test can still catch
    # an endpoint that doesn't validate the client either.
    client_ids = [c["client_id"] for c in src] or _FALLBACK_CLIENTS
    from_config = bool(src)
    token = _actor_token(ctx)

    accepted = None
    tested = 0
    for cid in client_ids[:6]:
        params = {"response_type": "code", "client_id": cid,
                  "redirect_uri": _ATTACKER_REDIRECT, "scope": "openid",
                  "state": "heimdall"}
        resp = _fire_authorize(ctx, authz, params, token)
        if resp is None:
            continue
        tested += 1
        where = _redirect_accepted(resp, _ATTACKER_HOST)
        if where:
            accepted = {"client": cid, "where": where}
            break

    if accepted:
        r = authz
        ctx.finding(
            id="oidc-redirect-uri-not-validated", owasp="A01", severity="HIGH",
            title=f"OAuth redirect_uri not validated on {r.method} {r.path} "
                  f"(code theft)",
            summary=(
                f"The authorization endpoint accepted an attacker-controlled "
                f"redirect_uri ({_ATTACKER_REDIRECT}) for a registered client "
                f"('{accepted['client']}') and redirected to / targeted it instead "
                "of rejecting it. An attacker crafts an authorize link for a real "
                "client with their own redirect_uri; when a victim authenticates, "
                "the authorization code (or token) is delivered to the attacker — "
                "full account takeover, not just an open redirect. Validate "
                "redirect_uri with EXACT string matching against the client's "
                "registered set; never prefix/substring match."
            ),
            evidence=f"  client_id={accepted['client']}  redirect_uri={_ATTACKER_REDIRECT}\n"
                     f"      -> {accepted['where']}",
            route=f"{r.method} {r.path}",
            request=f"{r.method} {r.path}  (client_id={accepted['client']}, "
                    f"redirect_uri={_ATTACKER_REDIRECT})",
            reproduction=(
                f"Send {r.method} {r.path} with response_type=code, "
                f"client_id={accepted['client']}, redirect_uri={_ATTACKER_REDIRECT}; "
                "the endpoint directs the flow at the attacker host. Complete it "
                "with a victim to capture their authorization code."
            ),
            references=[REFS["A01"], "https://portswigger.net/web-security/oauth",
                        "https://portswigger.net/web-security/oauth/"
                        "grant-types#authorization-code-flow"],
            tools=["Burp Suite", "curl"],
        )
        return True

    if tested and from_config:
        ctx.finding(
            id="oidc-redirect-uri-strict", owasp="A01", severity="SAFE",
            title="OAuth redirect_uri is validated (no code theft)",
            summary=(
                f"Drove {authz.method} {authz.path} with {tested} registered "
                f"client(s) and an attacker redirect_uri ({_ATTACKER_REDIRECT}); "
                "each was rejected rather than redirected to, consistent with exact "
                "redirect_uri matching. Note: PKCE enforcement, state/nonce "
                "validation, and authorization-code single-use + client-binding "
                "need a full authenticated flow and were not exercised here — "
                "verify them manually."
            ),
            route=f"{authz.method} {authz.path}",
            references=[REFS["A01"], "https://portswigger.net/web-security/oauth"],
        )
        return True
    if tested:
        ctx.finding(
            id="oidc-redirect-untested", owasp="A01", severity="INFO",
            title=f"Authorize endpoint {authz.method} {authz.path} not conclusively tested",
            summary=(
                "An OAuth authorize endpoint was found, but no registered client_id "
                "was available from config; generic client ids were rejected, so "
                "redirect_uri strictness couldn't be confirmed either way — not a "
                "clean bill of health. Supply a real client_id (or point --source at "
                "the client config) and re-run, or test manually with a registered "
                "client and an attacker redirect_uri."
            ),
            route=f"{authz.method} {authz.path}",
            references=[REFS["A01"], "https://portswigger.net/web-security/oauth"],
        )
        return True
    return False
