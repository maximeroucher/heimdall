"""Discovery: OpenAPI parsing, auth detection, source secret scanning."""

from conftest import make_spec

from heimdall.discovery import auth as auth_detect
from heimdall.discovery import openapi as oa
from heimdall.discovery import source


def test_parse_routes_extracts_methods_params_security(json_login_spec):
    rm = oa.parse_routes(json_login_spec)
    keys = {r.key for r in rm}
    assert "POST /core/auth/login" in keys
    assert "GET /users/{user_id}" in keys
    me = rm.first("/users/me", "GET")
    assert me.secured is True
    user = rm.first("/users/{user_id}", "GET")
    assert user.path_params == ["user_id"]
    items = rm.first("/items", "GET")
    assert items.secured is False
    assert [p["name"] for p in items.query_params] == ["q"]


def test_body_field_names(json_login_spec):
    rm = oa.parse_routes(json_login_spec)
    login = rm.first("/core/auth/login", "POST")
    assert set(oa.body_field_names(login)) == {"username", "password"}


def test_detect_auth_json_login(json_login_spec):
    ap = auth_detect.detect_auth(oa.parse_routes(json_login_spec))
    assert ap.login_path == "/core/auth/login"
    assert ap.login_style == "json"
    assert ap.username_field == "username"
    assert ap.password_field == "password"
    assert ap.register_path == "/core/auth/register"
    assert ap.me_path == "/users/me"
    assert ap.auth_kind == "bearer"


def test_detect_auth_oauth_form():
    spec = make_spec({
        "/auth/token": {"post": {
            "operationId": "token",
            "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {
                "type": "object",
                "properties": {"username": {"type": "string"},
                               "password": {"type": "string"},
                               "grant_type": {"type": "string"},
                               "scope": {"type": "string"}},
            }}}},
        }},
    })
    ap = auth_detect.detect_auth(oa.parse_routes(spec))
    assert ap.login_path == "/auth/token"
    assert ap.login_style == "oauth_password"
    assert ap.scopes_field == "scope"


def test_detect_auth_prefers_core_me_over_module_me():
    spec = make_spec({
        "/loans/users/me": {"get": {"operationId": "loans_me"}},
        "/users/me": {"get": {"operationId": "me"}},
    })
    ap = auth_detect.detect_auth(oa.parse_routes(spec))
    assert ap.me_path == "/users/me"


def test_detect_auth_register_scored_not_greedy():
    spec = make_spec({
        "/competition/volunteers/shifts/{shift_id}/register": {"post": {
            "operationId": "shift_register",
            "parameters": [{"name": "shift_id", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
        }},
        "/users/create": {"post": {
            "operationId": "create_user",
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object",
                "properties": {"email": {"type": "string"},
                               "password": {"type": "string"}},
            }}}},
        }},
    })
    ap = auth_detect.detect_auth(oa.parse_routes(spec))
    assert ap.register_path == "/users/create"


def test_detect_auth_apikey_and_cookie():
    spec = make_spec({"/x": {"get": {"operationId": "x"}}},
                     {"apikey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}})
    ap = auth_detect.detect_auth(oa.parse_routes(spec))
    assert ap.auth_kind == "apikey_header"
    assert ap.credential_name == "X-API-Key"

    spec2 = make_spec({"/x": {"get": {"operationId": "x"}}},
                      {"c": {"type": "apiKey", "in": "cookie", "name": "session"}})
    ap2 = auth_detect.detect_auth(oa.parse_routes(spec2))
    assert ap2.auth_kind == "cookie"
    assert ap2.credential_name == "session"


def test_scan_secrets_finds_key_and_private_pem(tmp_path):
    cfg = tmp_path / "config.yaml"
    priv = ("-----BEGIN PRIVATE KEY-----\\nMIIBVAIBADANBg\\n"
            "-----END PRIVATE KEY-----")
    cfg.write_text(
        "ACCESS_TOKEN_SECRET_KEY: \"azerty\"\n"
        "DATABASE_URL: postgres://u:p@h/db\n"
        f'RSA_PRIVATE_PEM_STRING: "{priv}"\n'
    )
    secrets = source.scan_secrets(str(tmp_path))
    kinds = {s.kind for s in secrets}
    assert "jwt_secret" in kinds
    assert "rsa_private_key" in kinds
    jwt = next(s for s in secrets if s.kind == "jwt_secret")
    assert jwt.value == "azerty"
    pk = next(s for s in secrets if s.kind == "rsa_private_key")
    assert "BEGIN PRIVATE KEY" in pk.value and "\n" in pk.value  # \n un-escaped


def test_jwt_secret_candidates_includes_source_and_wordlist():
    from heimdall.core.model import Secret
    cands = source.jwt_secret_candidates([Secret("K", "azerty", "x", "jwt_secret")])
    assert cands[0] == "azerty"        # source value tried first
    assert "secret" in cands           # built-in wordlist appended


def test_index_websocket_routes_finds_decorators_and_prefixes(tmp_path):
    mod = tmp_path / "endpoints.py"
    mod.write_text(
        "router = APIRouter()\n"
        '@router.websocket("/cdr/users/ws")\n'
        "async def ws_endpoint(ws): ...\n"
        '@app.websocket("/live")\n'
        "async def live(ws): ...\n"
        'app.add_websocket_route("/added/ws", handler)\n'
        'app.include_router(router, prefix="/api")\n'
    )
    routes = source.index_websocket_routes(str(tmp_path))
    paths = {p for p, _loc in routes}
    assert {"/cdr/users/ws", "/live", "/added/ws"} <= paths   # raw decorator paths
    assert "/api/cdr/users/ws" in paths                        # prefixed variant too
    assert all(":" in loc for _p, loc in routes)               # each has file:line


def test_is_me_path_matches_segments_not_substrings():
    # /me-style routes match on whole path segments...
    assert auth_detect._is_me_path("/me") is True
    assert auth_detect._is_me_path("/users/me") is True
    assert auth_detect._is_me_path("/api/v1/whoami") is True
    assert auth_detect._is_me_path("/account/self") is True
    assert auth_detect._is_me_path("/api/user") is True       # RealWorld current-user
    # ...but a substring like "me" inside "menu" must NOT (this picked /menu on DVR,
    # a public route, which then poisoned the JWT acceptance oracle).
    assert auth_detect._is_me_path("/menu") is False
    assert auth_detect._is_me_path("/members") is False
    assert auth_detect._is_me_path("/home") is False
    assert auth_detect._is_me_path("/users") is False         # plural list, not "me"
    assert auth_detect._is_me_path("/api/users") is False


def test_register_schema_and_required_fields_captured():
    # A register body with an extra required field beyond username/password must be
    # carried on the AuthProfile so self-registration can satisfy it.
    spec = make_spec({
        "/register": {"post": {"operationId": "register", "requestBody": {"content": {
            "application/json": {"schema": {
                "type": "object",
                "required": ["username", "password", "phone_number"],
                "properties": {"username": {"type": "string"},
                               "password": {"type": "string"},
                               "phone_number": {"type": "string"}},
            }}}}}},
    })
    ap = auth_detect.detect_auth(oa.parse_routes(spec))
    assert ap.register_path == "/register"
    assert ap.register_schema is not None
    assert set(ap.register_schema.get("required", [])) == {"username", "password", "phone_number"}
