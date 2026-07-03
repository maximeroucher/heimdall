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
_ME_HINTS = ("/me", "current-user", "current_user", "whoami", "users/me")
_USER_FIELDS = ("username", "email", "login", "user")
_PASS_FIELDS = ("password", "passwd", "pass", "secret")


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

    # -- header scheme from securitySchemes ------------------------------------
    schemes = (rm.components.get("securitySchemes") or {})
    for s in schemes.values():
        if not isinstance(s, dict):
            continue
        t = s.get("type")
        if t == "http" and s.get("scheme", "").lower() == "bearer":
            ap.header_scheme = "Bearer"
        elif t == "oauth2":
            ap.header_scheme = "Bearer"
        elif t == "apiKey":
            ap.header_scheme = "Bearer"  # header name handled by caller if needed

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
            ap.username_field = _pick_field(fields, _USER_FIELDS, "username")
            ap.password_field = _pick_field(fields, _PASS_FIELDS, "password")

    # -- register endpoint -----------------------------------------------------
    for r in rm.by_method("POST"):
        p = r.path.lower()
        oid = (r.operation_id or "").lower()
        if any(h in p or h in oid for h in _REGISTER_HINTS):
            ap.register_path = r.path
            ap.register_fields = body_field_names(r)
            break

    # -- "me" endpoint ---------------------------------------------------------
    for r in rm.by_method("GET"):
        p = r.path.lower()
        if any(h in p for h in _ME_HINTS):
            ap.me_path = r.path
            break

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
