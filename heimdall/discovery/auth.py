"""Detect how the target authenticates, from the OpenAPI doc + heuristics.

Handles the shapes seen in the wild across FastAPI apps:
  * JSON login  (``POST /core/auth/login`` {username,password} -> {access_token})
  * OAuth2 password/form flow  (``POST /auth/token`` form username+password)
  * a "simple token" password endpoint  (``POST /auth/simple_token``)
Falls back gracefully and records what it could not determine.
"""

from __future__ import annotations

import base64
import json

from ..core.model import AuthProfile, Route, RouteMap
from .openapi import body_field_names

_LOGIN_HINTS = ("login", "token", "signin", "sign-in", "authenticate", "session")
_LOGIN_NEG = ("refresh", "revoke", "logout", "reset", "forgot", "verify", "authorize")
_REGISTER_HINTS = ("register", "signup", "sign-up", "users/create", "account")
_ME_SEGMENTS = ("me", "whoami", "self", "current-user", "current_user")
_USER_FIELDS = ("username", "email", "login", "user")
_PASS_FIELDS = ("password", "passwd", "pass", "secret")


def _unwrap_envelope(schema: dict | None) -> tuple[str | None, dict]:
    """RealWorld / JSON:API style bodies nest credentials under a single wrapper
    object, e.g. ``{"user": {"email": .., "password": ..}}``. Detect a lone
    object-typed property whose sub-fields look like credentials and return
    ``(wrapper_key, sub_schema)`` so field detection and payload building target
    the nested object instead of seeing just ``["user"]``. Returns ``(None, schema)``
    when the body is already flat."""
    if not isinstance(schema, dict):
        return None, {}
    props = schema.get("properties")
    if not isinstance(props, dict) or len(props) != 1:
        return None, schema
    key, sub = next(iter(props.items()))
    subprops = sub.get("properties") if isinstance(sub, dict) else None
    if not isinstance(subprops, dict):
        return None, schema
    names = {n.lower() for n in subprops}
    if any(u in names for u in _USER_FIELDS) or any(p in names for p in _PASS_FIELDS):
        return key, sub
    return None, schema


def _is_me_path(path: str) -> bool:
    """A 'current user' echo route. Match whole path *segments* so ``/menu`` is
    not mistaken for ``/me`` (naive substring matching picked /menu on DVR, which
    then poisoned every downstream auth probe that used it as an oracle)."""
    segs = [s for s in path.lower().strip("/").split("/") if s]
    return any(s in _ME_SEGMENTS for s in segs)


def _content_types(route: Route) -> list[str]:
    rb = route.raw.get("requestBody", {})
    content = rb.get("content", {}) if isinstance(rb, dict) else {}
    return list(content.keys())


def _score_login(route: Route) -> int:
    if route.method != "POST":
        return -1
    p = route.path.lower()
    oid = (route.operation_id or "").lower()
    if any(n in p or n in oid for n in _LOGIN_NEG):
        return -1
    score = 0
    if any(h in p for h in _LOGIN_HINTS):
        score += 3
    if any(h in oid for h in _LOGIN_HINTS):
        score += 2
    fields = [f.lower() for f in body_field_names(route)]
    if any(u in fields for u in _USER_FIELDS):
        score += 2
    if any(pw in fields for pw in _PASS_FIELDS):
        score += 3
    if "application/x-www-form-urlencoded" in _content_types(route):
        score += 1  # classic OAuth2PasswordRequestForm
    return score


def _pick_field(fields: list[str], candidates: tuple[str, ...], default: str) -> str:
    low = {f.lower(): f for f in fields}
    for c in candidates:
        if c in low:
            return low[c]
    return default


def detect_auth(rm: RouteMap) -> AuthProfile:
    ap = AuthProfile()

    # -- auth kind + header scheme from securitySchemes ------------------------
    # Collect every declared scheme, then pick a primary: a token-in-Authorization
    # scheme wins (most APIs' main path), else an API-key / cookie / basic scheme.
    schemes = (rm.components.get("securitySchemes") or {})
    found: list[tuple[str, str]] = []   # (kind, credential_name)
    for s in schemes.values():
        if not isinstance(s, dict):
            continue
        t = s.get("type")
        if t == "http" and s.get("scheme", "").lower() == "bearer":
            found.append(("bearer", ""))
        elif t == "http" and s.get("scheme", "").lower() == "basic":
            found.append(("basic", ""))
        elif t in ("oauth2", "openIdConnect"):
            found.append(("bearer", ""))
        elif t == "apiKey":
            loc, nm = s.get("in"), s.get("name", "")
            if loc == "header":
                found.append(("apikey_header", nm))
            elif loc == "query":
                found.append(("apikey_query", nm))
            elif loc == "cookie":
                found.append(("cookie", nm))
    for pref in ("bearer", "apikey_header", "cookie", "apikey_query", "basic"):
        match = next((f for f in found if f[0] == pref), None)
        if match:
            ap.auth_kind, ap.credential_name = match
            break
    ap.header_scheme = "Bearer"

    # -- login endpoint --------------------------------------------------------
    best, best_score = None, 0
    for r in rm.by_method("POST"):
        sc = _score_login(r)
        if sc > best_score:
            best, best_score = r, sc
    if best is not None:
        ap.login_path = best.path
        fields = body_field_names(best)
        cts = _content_types(best)
        if "application/x-www-form-urlencoded" in cts or "multipart/form-data" in cts:
            ap.login_style = "form"
            # FastAPI OAuth2PasswordRequestForm is always username/password.
            ap.username_field = _pick_field(fields, ("username",), "username")
            ap.password_field = _pick_field(fields, ("password",), "password")
            if "grant_type" in [f.lower() for f in fields] or "scope" in [f.lower() for f in fields]:
                ap.login_style = "oauth_password"
                ap.scopes_field = "scope"
        else:
            ap.login_style = "json"
            wrapper, eff = _unwrap_envelope(best.body_schema)
            ap.login_wrapper = wrapper
            if wrapper:
                fields = list((eff.get("properties") or {}).keys())
            ap.username_field = _pick_field(fields, _USER_FIELDS, "username")
            ap.password_field = _pick_field(fields, _PASS_FIELDS, "password")

    # -- register endpoint -----------------------------------------------------
    # Score candidates so a nested feature route like
    # /competition/volunteers/shifts/{id}/register never beats real account
    # signup: reward register/signup hints + an email/password body, and a
    # no-path-param account-ish path; penalize deep module paths.
    def _score_register(r: Route) -> int:
        p, oid = r.path.lower(), (r.operation_id or "").lower()
        blob = f"{p} {oid}"
        if not any(h in blob for h in _REGISTER_HINTS):
            return -1
        score = 0
        _wrap, _eff = _unwrap_envelope(r.body_schema)
        fields = ([f.lower() for f in (_eff.get("properties") or {})] if _wrap
                  else [f.lower() for f in body_field_names(r)])
        if any(u in fields for u in _USER_FIELDS):
            score += 2
        if any(pw in fields for pw in _PASS_FIELDS):
            score += 2
        if not r.path_params:
            score += 2                      # account signup takes no object id
        if "/users" in p or "account" in p:
            score += 2
        score -= p.count("/")               # prefer shallow (top-level) routes
        return score
    reg_best, reg_score = None, 0
    for r in rm.by_method("POST"):
        sc = _score_register(r)
        if sc > reg_score:
            reg_best, reg_score = r, sc
    if reg_best is not None:
        ap.register_path = reg_best.path
        reg_wrapper, reg_eff = _unwrap_envelope(reg_best.body_schema)
        ap.register_wrapper = reg_wrapper
        if reg_wrapper:
            ap.register_schema = reg_eff
            ap.register_fields = list((reg_eff.get("properties") or {}).keys())
        else:
            ap.register_fields = body_field_names(reg_best)
            ap.register_schema = reg_best.body_schema

    # -- "me" endpoint ---------------------------------------------------------
    # Prefer the least-nested current-user route (core /users/me over a
    # module-scoped /loans/users/me, which needs extra scope and misleads probes).
    me_hits = [r.path for r in rm.by_method("GET") if _is_me_path(r.path)]
    if me_hits:
        ap.me_path = min(me_hits, key=lambda p: (p.count("/"), len(p)))

    # -- logout ----------------------------------------------------------------
    for r in rm.by_method("POST", "GET", "DELETE"):
        if "logout" in r.path.lower():
            ap.logout_path = r.path
            break

    return ap


# ── JWT helpers ──────────────────────────────────────────────────────────────

def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    """Return (header, claims) without verifying. None if not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims


def enrich_with_token(ap: AuthProfile, token: str) -> None:
    """Fold JWT facts (alg, header, claims) into the AuthProfile."""
    decoded = decode_jwt(token)
    if decoded is None:
        ap.is_jwt = False
        return
    header, claims = decoded
    ap.is_jwt = True
    ap.jwt_header = header
    ap.jwt_claims = claims
    ap.jwt_alg = header.get("alg")
