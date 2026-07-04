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


def test_synth_field_fills_required_types():
    from heimdall.bootstrap.principals import _synth_field
    kw = dict(ident="a@b.co", username="atk", password="Pw!23")
    # canonical fields resolve to the login triple
    assert _synth_field("email", {"type": "string"}, **kw) == "a@b.co"
    assert _synth_field("password", {"type": "string"}, **kw) == "Pw!23"
    assert _synth_field("username", {"type": "string"}, **kw) == "atk"
    # extra required fields get type/format/name-appropriate values (not dropped)
    assert isinstance(_synth_field("phone_number", {"type": "string"}, **kw), str)
    assert "@" not in _synth_field("phone_number", {"type": "string"}, **kw)
    assert _synth_field("age", {"type": "integer"}, **kw) == 1
    assert _synth_field("accept_tos", {"type": "boolean"}, **kw) is False
    assert _synth_field("tags", {"type": "array"}, **kw) == []
    # nullable Optional[str] (anyOf) still yields a typed guess, not None
    opt = {"anyOf": [{"type": "string"}, {"type": "null"}]}
    assert _synth_field("first_name", opt, **kw) == "Heim"
    # enum picks a valid member
    assert _synth_field("role", {"enum": ["user", "admin"]}, **kw) == "user"
