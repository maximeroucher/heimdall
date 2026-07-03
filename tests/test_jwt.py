"""JWT helpers: decode, signature crack oracle, minting, scope discovery."""

import jwt as pyjwt

from heimdall.bootstrap import minting
from heimdall.core.model import AppProfile, RouteMap, Secret
from heimdall.discovery import auth as auth_detect


def _tok(claims, secret="azerty"):
    return pyjwt.encode(claims, secret, algorithm="HS256")


def test_decode_jwt():
    t = _tok({"sub": "u1", "scopes": "auth"})
    header, claims = auth_detect.decode_jwt(t)
    assert header["alg"] == "HS256"
    assert claims["sub"] == "u1"
    assert auth_detect.decode_jwt("not.a.jwt") is None
    assert auth_detect.decode_jwt("opaque") is None


def test_sig_matches_is_exact():
    t = _tok({"sub": "u1"}, secret="azerty")
    assert minting._sig_matches(t, "azerty") is True
    assert minting._sig_matches(t, "wrong") is False


def test_recover_secret():
    t = _tok({"sub": "u1"}, secret="azerty")
    p = AppProfile(base_url="http://x", secrets=[Secret("K", "azerty", "s", "jwt_secret")])
    assert minting.recover_secret(p, t) == "azerty"
    # unknown secret -> None
    p2 = AppProfile(base_url="http://x", secrets=[Secret("K", "nope", "s", "jwt_secret")])
    assert minting.recover_secret(p2, t) is None


def test_mint_reissues_with_new_sub_and_scope():
    t = _tok({"sub": "victim", "scopes": "auth", "iat": 1, "exp": 2}, secret="azerty")
    forged = minting.mint(t, "azerty", sub="attacker", scopes="API")
    # forged must verify under the same secret and carry the new claims.
    claims = pyjwt.decode(forged, "azerty", algorithms=["HS256"])
    assert claims["sub"] == "attacker"
    assert claims["scopes"] == "API"
    assert minting._sig_matches(forged, "azerty")


def test_declared_scopes_from_openapi():
    spec = {"components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {
        "authorizationCode": {"scopes": {"API": "d", "openid": "d"}}}}}}}
    rm = RouteMap(openapi=spec, components=spec["components"])
    p = AppProfile(base_url="http://x", routes=rm)
    assert minting.declared_scopes(p) == "API openid"
