"""Mint usable tokens for provisioned users by chaining a recovered signing key.

Some apps hand out scope-limited login tokens (e.g. an OAuth 'auth' scope that
can't call API routes), so a freshly-provisioned account can log in yet reach
nothing — which would make access-control results meaningless. When Heimdall has
already recovered the HS* signing secret (the A02 crack), it can re-issue a
token for that same user with the API scopes the app declares in its OpenAPI
document. This is exactly the impact of a guessable secret, turned into a
testing primitive: a correctly-scoped token for an account we legitimately own.

If the secret is NOT recovered, minting is unavailable and the caller falls back
to whatever the login endpoint returned.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64encode

from ..core.model import AppProfile
from ..discovery.auth import decode_jwt
from ..discovery.source import jwt_secret_candidates


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _sig_matches(token: str, secret: str) -> bool:
    signing_input, _, sig = token.rpartition(".")
    if not signing_input or not sig:
        return False
    try:
        expected = _b64(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(expected, sig)


def recover_secret(profile: AppProfile, token: str) -> str | None:
    """Return the HS256 signing secret if a candidate matches ``token``'s sig."""
    decoded = decode_jwt(token)
    if decoded is None or not str(decoded[0].get("alg", "")).upper().startswith("HS"):
        return None
    for secret in jwt_secret_candidates(profile.secrets):
        if _sig_matches(token, secret):
            return secret
    return None


def declared_scopes(profile: AppProfile) -> str:
    """Space-joined OAuth2 scopes declared in the OpenAPI securitySchemes."""
    schemes = profile.routes.components.get("securitySchemes", {}) or {}
    scopes: set[str] = set()
    for s in schemes.values():
        if isinstance(s, dict) and s.get("type") == "oauth2":
            for flow in (s.get("flows") or {}).values():
                scopes.update((flow.get("scopes") or {}).keys())
    return " ".join(sorted(scopes))


def _scope_claim_key(claims: dict) -> str | None:
    for k in ("scopes", "scope", "scp", "permissions"):
        if k in claims:
            return k
    return None


def mint(template_token: str, secret: str, *, sub: str | None = None,
         scopes: str | None = None, ttl: int = 3600) -> str | None:
    """Re-sign a token modelled on ``template_token`` (same header/claim shape),
    optionally swapping the subject and scope claim, using the recovered secret."""
    decoded = decode_jwt(template_token)
    if decoded is None:
        return None
    header, claims = decoded
    new = dict(claims)
    if sub is not None:
        for k in ("sub", "user_id", "uid", "id"):
            if k in new:
                new[k] = sub
                break
        else:
            new["sub"] = sub
    if scopes is not None:
        key = _scope_claim_key(new) or "scopes"
        # preserve list-vs-string shape of the original claim
        if isinstance(new.get(key), list):
            new[key] = scopes.split()
        else:
            new[key] = scopes
    now = int(time.time())
    if "iat" in new:
        new["iat"] = now
    if "exp" in new:
        new["exp"] = now + ttl
    h = _b64(json.dumps({**header, "alg": "HS256"}, separators=(",", ":")).encode())
    p = _b64(json.dumps(new, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"
