"""Module registry + small module helpers."""

from heimdall.modules import a01_access_control as a01
from heimdall.modules.base import looks_like_id_param


def test_all_modules_register():
    from heimdall.modules.base import REGISTRY, ordered
    from heimdall.runner import _import_all_modules
    _import_all_modules()
    keys = {m.key for m in ordered()}
    for expected in ("a01", "a02", "a03", "a05", "a06", "a07", "a10", "csrf", "race", "session", "sast"):
        assert expected in keys, expected
    assert REGISTRY["race"].destructive is True
    assert REGISTRY["a01"].destructive is False


def test_a01_framework_utility_paths_are_public():
    """Root/routes/test/metrics etc. are public utility endpoints — an app with a
    global security scheme must not have them flagged as auth-required-reachable."""
    assert a01._is_public_by_design("/", "root")
    assert a01._is_public_by_design("/routes", "get_routes")
    assert a01._is_public_by_design("/test", "test_endpoint")
    assert a01._is_public_by_design("/metrics", "metrics")
    # exact match only — no substring false friends, still catches real routes
    assert not a01._is_public_by_design("/latest", "get_latest")
    assert not a01._is_public_by_design("/users/{id}", "get_user_by_id")


def test_data_exposure_skips_schema_metadata_fields():
    """A placeholder/example value that LOOKS like a key is illustrative, not a
    leak; the same value under a real field name is flagged."""
    from heimdall.modules import data_exposure as de

    secretish = "Xk9mQ2wL8pR4tY7nZ3vB"
    assert de._sensitive("placeholder", secretish, False, set()) is None
    assert de._sensitive("example", secretish, False, set()) is None
    assert de._sensitive("api_key", secretish, False, set()) is not None


def test_websocket_authgate_recognizes_common_rejection_frames():
    """A WS that rejects an unauthenticated connect by sending an auth-error frame
    must be recognized as gated — otherwise it's falsely reported HIGH "serves data
    without authentication". Legit data streams must stay non-gated so a genuinely
    open socket still flags."""
    from heimdall.modules.websocket import _looks_authgate

    for frame in ("Could not validate credentials", "authentication required",
                  "login required", "permission denied", "Unauthorized",
                  "Not authenticated", "Access is not allowed"):
        assert _looks_authgate(frame, "data"), frame
    for legit in ('{"prices":[1,2,3],"symbol":"BTC"}', '{"msg":"welcome to the chat"}',
                  '{"event":"tick","value":42}'):
        assert not _looks_authgate(legit, "data"), legit
    assert _looks_authgate("", "closed")          # transport close = rejection
    assert not _looks_authgate("", "timeout")     # timeout is not a rejection signal


def test_xxe_leak_detection_is_structural_not_substring():
    """XXE file-read confirmation must match a structural /etc/passwd account line,
    not a bare `/bin/bash` / `daemon:` substring that appears in env dumps or
    stack traces (which produced a false HIGH 'confirmed XXE')."""
    from heimdall.modules import xxe

    class Resp:
        def __init__(self, text):
            self.text = text

    leak = lambda t: xxe._leaked(Resp(t))
    # real leaks (root present, or only a non-root account) confirm
    assert leak("root:x:0:0:root:/root:/bin/bash\n") is not None
    assert leak("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n") is not None
    assert leak("[fonts]\r\n[extensions]\r\n") is not None                # win.ini
    # responses that merely mention a shell path / 'daemon:' but aren't passwd → quiet
    assert leak('{"env":{"SHELL":"/bin/bash","PATH":"/usr/bin"}}') is None
    assert leak('Traceback: exec("/bin/bash") in worker daemon: restarting') is None
    assert leak('<gpx><wpt><name>heimdall</name></wpt></gpx>') is None
    assert leak('{"created":"12:00:00","uid":0,"gid":0}') is None


def test_improper_inventory_config_json_needs_real_secret_value():
    """The config.json probe must require a secret-ish key with a substantive
    value — a public SPA config with null/empty/placeholder values is not a leak,
    and secret_key / API_KEY / JWT values must be caught (the old exact-word
    regex missed them)."""
    from heimdall.modules.improper_inventory import _PROBES

    sig = next(s for p, s, _sev, _l in _PROBES if p == "config.json")
    # real leaks flag
    assert sig.search('{"database":{"password":"S3cr3tP@ssw0rd!"}}')
    assert sig.search('{"secret_key":"sk_live_abc123def456ghi789"}')
    assert sig.search('{"API_KEY": "AIzaSyD-abc123def456ghi"}')
    assert sig.search('{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}')
    # public / empty / placeholder configs stay quiet
    assert not sig.search('{"token": null, "apiUrl":"/api"}')
    assert not sig.search('{"key": "", "feature": true}')
    assert not sig.search('{"password": "CHANGEME"}')
    assert not sig.search('{"apiUrl":"https://api.example.com","timeout":30}')


def test_csrf_reads_samesite_of_the_session_cookie():
    """When a login sets several cookies, the CSRF verdict must reflect the SameSite
    of the auth cookie, not whichever SameSite appears first in the header."""
    from heimdall.modules.csrf import _session_samesite

    # csrftoken=Lax listed first, but the HttpOnly session cookie is None → none
    got, name = _session_samesite(
        "csrftoken=abc; SameSite=Lax, sessionid=xyz; SameSite=None; HttpOnly")
    assert got == "none" and name == "sessionid"
    # a None analytics cookie first, session cookie is Lax → lax
    got, _ = _session_samesite("other=1; SameSite=None, sessionid=xyz; SameSite=Lax; HttpOnly")
    assert got == "lax"
    # the comma inside an Expires date must not split the cookie
    got, _ = _session_samesite(
        "sessionid=x; Expires=Wed, 21 Oct 2025 07:28:00 GMT; SameSite=Lax; HttpOnly")
    assert got == "lax"
    # single strict session cookie
    assert _session_samesite("session=x; SameSite=Strict; HttpOnly")[0] == "strict"


def test_mass_assignment_skips_nondeterministic_server_fields():
    """A server-only field that varies between two identical baseline creates
    (random bucket, cache/timestamp flag) must not be injected into — a
    coincidental match (a boolean is 50/50) can't be attributed to over-binding.
    Deterministic fields are still injected; without a second baseline, the gate
    degrades to the prior single-baseline behaviour."""
    from heimdall.modules.mass_assignment import _injectable_fields, _MARK_STR, _MARK_NUM

    cands = ["is_admin", "bucket", "role", "created_at", "token_flag", "missing"]
    o0 = {"is_admin": False, "bucket": False, "role": "user", "created_at": 100, "token_flag": True}
    o0b = {"is_admin": False, "bucket": True, "role": "user", "created_at": 200, "token_flag": True}
    inj = _injectable_fields(cands, o0, o0b)
    assert inj == {"is_admin": True, "role": _MARK_STR, "token_flag": False}
    assert "bucket" not in inj and "created_at" not in inj      # oscillating + timestamp dropped
    # present in o0 but absent in the second baseline → non-deterministic → skip
    assert _injectable_fields(["x"], {"x": False}, {}) == {}
    # no second baseline → single-baseline fallback (tests everything typable)
    assert _injectable_fields(cands, o0, None) == {
        "is_admin": True, "bucket": True, "role": _MARK_STR,
        "created_at": _MARK_NUM, "token_flag": False}


def test_a03_boolean_sqli_needs_reproducible_stable_divergence():
    """Boolean SQLi is confirmed only when TRUE/FALSE diverge reproducibly and
    each side is stable — a non-deterministic body (timestamps, counts, tokens)
    must not be mistaken for an injection."""
    from heimdall.modules.a03_injection import _confirmed_boolean_sqli
    import itertools

    class R:
        def __init__(self, status, text):
            self.status_code = status
            self.text = text

    T, F = 'a" OR "1"="1', 'a" OR "1"="2'
    # genuine injection: TRUE=all rows (big), FALSE=none (small), stable → flag
    det = lambda p: R(200, "x" * 2000 if p.rstrip().endswith("1") else "[]")
    assert _confirmed_boolean_sqli(det, T, F) is not None
    # status-class divergence, stable → flag
    st = lambda p: R(200 if p.rstrip().endswith("1") else 500, "ok")
    assert _confirmed_boolean_sqli(st, "1 OR 1=1", "1 OR 1=2") is not None
    # reflecting-only (identical bodies) → quiet
    assert _confirmed_boolean_sqli(lambda p: R(200, "same"), T, F) is None
    # non-deterministic body length every call → quiet
    c = itertools.count()
    assert _confirmed_boolean_sqli(lambda p: R(200, "n" * (100 + next(c) * 137 % 900)), T, F) is None


def test_host_header_body_reflection_requires_url_context():
    """A poisoned Host reflected into a body URL (reset link) flags; a debug /
    header-echo endpoint that merely mirrors the request header value as JSON or
    prose is not URL construction and must stay quiet. Location and response
    headers (inherently URL-bearing) still match on substring."""
    from heimdall.modules import host_header as hh

    C = hh._CANARY

    class Resp:
        def __init__(self, status=200, headers=None, body=""):
            self.status_code = status
            self.headers = headers or {}
            self.text = body

    hit = lambda r: hh._canary_in(r) is not None
    assert hit(Resp(302, headers={"Location": f"https://{C}/reset?token=abc"}))
    assert hit(Resp(200, body=f'<a href="https://{C}/reset?token=abc">x</a>'))
    assert hit(Resp(200, body=f'window.location="//{C}/verify"'))
    assert hit(Resp(200, headers={"Link": f"<https://{C}/x>; rel=canonical"}))
    # header-echo / prose mention: reflected but not a URL → quiet
    assert not hit(Resp(200, body='{"headers":{"x-forwarded-host":"' + C + '"}}'))
    assert not hit(Resp(200, body=f"Received request for host {C} (logged)"))


def test_open_redirect_matches_effective_nav_host_not_substring():
    """The canary must be the browser's effective navigation host (or a subdomain
    of it) — not merely a substring of the Location. Kills the classic FPs:
    userinfo @, canary-in-path, and a lookalike domain that contains the canary."""
    from heimdall.modules import open_redirect as orr

    C = orr._CANARY_HOST

    class Resp:
        def __init__(self, status, location="", body=""):
            self.status_code = status
            self.headers = {"Location": location} if location else {}
            self.text = body

    hit = lambda r: orr._redirects_to(r, C) is not None
    # genuine open redirects (the payload forms we send) must flag
    assert hit(Resp(302, location=f"https://{C}/"))
    assert hit(Resp(302, location=f"//{C}/"))
    assert hit(Resp(302, location=f"https:{C}"))
    assert hit(Resp(302, location=f"https://trusted.example.{C}/"))   # subdomain of canary
    assert hit(Resp(302, location=f"/\\{C}/"))                        # backslash bypass
    assert hit(Resp(200, body=f"<script>window.location='https://{C}/x'</script>"))
    # safe redirects that merely mention the canary must stay quiet
    assert not hit(Resp(302, location=f"https://{C}@legit.example.com/"))     # userinfo
    assert not hit(Resp(302, location=f"https://legit.example.com/go/https://{C}/"))  # in path
    assert not hit(Resp(302, location="https://evil-heimdall-redir.test.attacker-really.com/"))
    assert not hit(Resp(302, location=f"/{C}"))                        # path-absolute
    assert not hit(Resp(200, location=f"https://{C}/"))                # not a 3xx
    assert not hit(Resp(200, body=f"<p>never visit {C}</p>"))          # mention, no redirect


def test_provision_admin_where_uses_boolean_literals():
    """The admin-flag filter must use SQL TRUE/FALSE, not 1/0 — Postgres rejects
    `boolean = integer`, which broke --provision on every Postgres app with a
    boolean admin column (SQLite/MySQL coerced, so it went unnoticed)."""
    from heimdall.bootstrap.provision import _admin_where

    assert _admin_where("is_superuser", True) == ' WHERE "is_superuser" = TRUE'
    assert _admin_where("is_superuser", False) == ' WHERE "is_superuser" = FALSE'
    assert _admin_where(None, True) == ""       # no admin flag → no filter
    # never emit an integer literal that Postgres would reject against a boolean
    assert "= 1" not in _admin_where("f", True) and "= 0" not in _admin_where("f", False)


def test_data_exposure_public_metadata_kid_not_a_leak(tmp_path):
    """A high-entropy `kid` (public Key ID) on JWKS / OpenID-discovery is public
    by design, not a data leak; but a PRIVATE JWK component (d/p/q) published in a
    key set IS still flagged."""
    from types import SimpleNamespace
    from heimdall.modules import data_exposure as de

    r = lambda p: SimpleNamespace(path=p, operation_id="")
    assert de._is_public_metadata(r("/.well-known/jwks.json"))
    assert de._is_public_metadata(r("/.well-known/openid-configuration"))
    assert de._is_public_metadata(r("/tenant/jwks"))
    assert not de._is_public_metadata(r("/api/users"))
    # a public key id is high-entropy but must NOT be treated as a secret...
    assert de._entropy_secret("xnsr1uKqZ8pL3mW9tB7vC2yD4fH6gJ0")  # (it IS high-entropy)
    # ...while private JWK members remain in the flag set for the metadata guard
    for priv in ("d", "p", "q", "dp", "dq", "qi", "k"):
        assert priv in de._JWK_PRIVATE_FIELDS


def test_a07_oauth_token_endpoint_is_not_a_password_login():
    """OAuth token-endpoint protocol errors mean 'not a password login' (skip the
    rate-limit finding); invalid_grant is EXCLUDED because it is the genuine
    wrong-credentials error for a password grant."""
    from heimdall.modules.a07_auth import _OAUTH_NONLOGIN_ERRORS

    assert "invalid_client" in _OAUTH_NONLOGIN_ERRORS
    assert "unsupported_grant_type" in _OAUTH_NONLOGIN_ERRORS
    assert "invalid_request" in _OAUTH_NONLOGIN_ERRORS
    assert "invalid_grant" not in _OAUTH_NONLOGIN_ERRORS   # that IS a real login rejection


def test_sast_skips_developer_tooling_dirs(tmp_path):
    """SAST must not scan developer tooling (dev/, scripts/, code-generation, …):
    their requests.get / os.system run at dev time, never from an HTTP handler, so
    flagging them as app SSRF/cmdi sinks is a false positive."""
    from heimdall.modules.sast import _iter_py

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x = 1\n")
    for d in ("dev", "scripts", "tools", "examples", "docs"):
        sub = tmp_path / d
        sub.mkdir()
        (sub / "gen.py").write_text("import requests; requests.get(url)\n")
    (tmp_path / "dev" / "code-generation").mkdir()
    (tmp_path / "dev" / "code-generation" / "x.py").write_text("requests.get(u)\n")

    scanned = {p.replace(str(tmp_path) + "/", "") for p in _iter_py(str(tmp_path))}
    assert scanned == {"app/main.py"}, scanned


def test_a07_recognizes_lockout_and_rate_limit_status_codes():
    """Brute-force protection is signalled by 429 (IP/global rate limit) AND 423
    (per-account lockout — the common FastAPI defence). Recognising only 429 would
    false-positive 'no rate limiting' on every lockout-based app (e.g. mealie)."""
    from heimdall.modules.a07_auth import _THROTTLE_CODES

    assert 429 in _THROTTLE_CODES
    assert 423 in _THROTTLE_CODES


def test_data_exposure_own_token_skipped_cross_user_flagged():
    """A JWT echoed on a /me or token-refresh response that carries the CALLER's
    own identity is not a leak; another user's token (or a token when we hold no
    caller token) still flags. The generic sub='access' marker must not be
    mistaken for a shared identity."""
    import base64
    import json as _json
    from heimdall.modules import data_exposure as de

    def jwt(claims):
        b = lambda o: base64.urlsafe_b64encode(_json.dumps(o).encode()).rstrip(b"=").decode()
        return f"{b({'alg':'HS256','typ':'JWT'})}.{b(claims)}.sig"

    caller = jwt({"username": "alice", "exp": 1, "sub": "access"})
    same = jwt({"username": "alice", "exp": 999, "sub": "access"})   # refreshed, same user
    other = jwt({"username": "bob", "exp": 1, "sub": "access"})       # different user

    assert de._is_own_token(same, caller)        # caller's own token, refreshed → skip
    assert de._is_own_token(caller, caller)      # identical string → skip
    assert not de._is_own_token(other, caller)   # another user's token → still a leak
    assert not de._is_own_token(same, None)      # no caller token → cannot vouch → flag
    assert not de._is_own_token("not-a-jwt", caller)
    # sub='access' alone (no identity claim) must NOT count as same identity
    a = jwt({"sub": "access", "exp": 1})
    b = jwt({"sub": "access", "exp": 2})
    assert not de._is_own_token(a, b)


def test_data_exposure_iban_spaces_and_base64_magic():
    """Space-formatted IBANs are caught (checksum-validated on a stripped copy);
    base64 file/image data (magic prefix) is not a secret."""
    from heimdall.modules import data_exposure as de

    # FN fix: IBANs are commonly grouped with spaces
    assert de._sensitive("note", "GB82 WEST 1234 5698 7654 32", False, set()) is not None
    assert de._sensitive("iban", "GB82WEST12345698765432", False, set()) is not None  # contiguous still ok
    # FP fix: base64-encoded binary files (PNG/JPEG magic) are not secrets
    assert de._sensitive("thumb", "iVBORw0KGgoAAAANSUhEUg", False, set()) is None      # PNG
    assert de._sensitive("img", "/9j/4AAQSkZJRgABAQEAYA", False, set()) is None         # JPEG
    # a genuine entropy secret is unaffected
    assert de._sensitive("api_key", "Xk9mQ2wL8pR4tY7nZ3vB", False, set()) is not None


def test_data_exposure_token_expected_on_auth_route():
    """A token/JWT returned by a token-issuing auth route (login/refresh) is
    expected, not a leak; the same token on a normal route IS a leak, and a
    leaked password fires even on an auth route."""
    from heimdall.modules import data_exposure as de

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc123def456ghi789xyz"
    assert de._sensitive("access_token", jwt, True, set()) is None      # auth route
    assert de._sensitive("access_token", jwt, False, set()) is not None  # normal route
    # a plaintext password is never expected, even on an auth route
    assert de._sensitive("access_token", "Summer2024!", True, {"Summer2024!"}) is not None


def test_extract_token_nested_envelopes():
    """A nested {"token": {"access_token": …}} envelope yields the STRING token,
    never the inner dict."""
    from heimdall.bootstrap.principals import _extract_token

    assert _extract_token({"access_token": "abc"}) == "abc"
    assert _extract_token({"token": {"access_token": "abc", "refresh_token": "r"}}) == "abc"
    assert _extract_token({"data": {"token": {"access_token": "abc"}}}) == "abc"
    assert _extract_token({"token": {"foo": "bar"}}) is None
    r = _extract_token({"token": {"access_token": "abc"}})
    assert isinstance(r, str)


def test_decode_jwt_rejects_non_string():
    from heimdall.discovery.auth import decode_jwt

    assert decode_jwt({"access_token": "x"}) is None
    assert decode_jwt(None) is None
    assert decode_jwt("not.a.jwt.here.xx") is None


def test_openapi_versioned_candidates_and_scrape_regex():
    """Versioned openapi paths are candidates, and the docs-scrape regex extracts
    a custom openapi_url from Swagger/ReDoc HTML."""
    from heimdall.discovery.openapi import OPENAPI_CANDIDATES, _OPENAPI_HREF_RE

    assert "/v1/openapi.json" in OPENAPI_CANDIDATES
    m = _OPENAPI_HREF_RE.search("const ui = SwaggerUIBundle({url: '/v1/openapi.json'})")
    assert m and m.group(1) == "/v1/openapi.json"
    m2 = _OPENAPI_HREF_RE.search('<redoc spec-url="/api/v2/openapi.json"></redoc>')
    assert m2 and m2.group(1) == "/api/v2/openapi.json"


def test_detect_db_kind():
    """The DB engine is detected from the driver package or a connection URL, so
    Heimdall can spawn the matching throwaway on its own."""
    import tempfile
    from pathlib import Path

    from heimdall.discovery.source import detect_db_kind

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for sub, imp, expect in [("m", "from pymongo import MongoClient", "mongo"),
                                 ("p", "import asyncpg", "postgres"),
                                 ("y", "import pymysql", "mysql"),
                                 ("s", "import sqlite3", "sqlite")]:
            (root / sub).mkdir()
            (root / sub / "a.py").write_text(imp + "\n")
            assert detect_db_kind(str(root / sub)) == expect, sub
    # an explicit connection URL's driver wins
    assert detect_db_kind(None, "postgresql+asyncpg://u:p@h/db") == "postgres"
    assert detect_db_kind(None, "mongodb+srv://h/db") == "mongo"
    assert detect_db_kind(None, "mysql://u:p@h/db") == "mysql"


def test_detect_db_env_vars_and_build_launch_env():
    """Env-var names the app reads are detected and populated with the throwaway
    DB's real coordinates (not a guessed single URL name)."""
    import tempfile
    from pathlib import Path

    from heimdall.bootstrap.testdb import _DOCKER_DB, _build_launch_env
    from heimdall.discovery.source import detect_db_env_vars

    with tempfile.TemporaryDirectory() as d:
        app = Path(d) / "app"
        app.mkdir()
        (app / "db.py").write_text(
            "from os import getenv\n"
            "getenv('MONGO_HOST'); getenv('MONGO_PORT'); getenv('MONGO_USERNAME')\n"
            "getenv('MONGO_PASSWORD'); getenv('MONGO_DATABASE')\n")
        ev = detect_db_env_vars(str(app))
    assert {"MONGO_HOST", "MONGO_PORT", "MONGO_USERNAME", "MONGO_PASSWORD",
            "MONGO_DATABASE"} <= ev
    env = _build_launch_env("mongo", "127.0.0.1", 5555, _DOCKER_DB["mongo"],
                            "mongodb://heimdall:heimdall@127.0.0.1:5555/?authSource=admin",
                            "DATABASE_URL", ev)
    assert env["MONGO_HOST"] == "127.0.0.1" and env["MONGO_PORT"] == "5555"
    assert env["MONGO_USERNAME"] == "heimdall" and env["MONGO_PASSWORD"] == "heimdall"
    assert env["MONGO_DATABASE"] == "heimdall"
    assert env["MONGO_URL"].endswith("authSource=admin")


def test_file_upload_static_mount_detection(tmp_path):
    """StaticFiles mount prefixes are detected from source (so a served-back
    upload can be confirmed as stored XSS) plus common conventions."""
    from heimdall.core.context import Context
    from heimdall.core.model import AppProfile
    from heimdall.modules import file_upload as fu

    src = tmp_path / "app"
    src.mkdir()
    (src / "main.py").write_text(
        "from fastapi.staticfiles import StaticFiles\n"
        "app.mount('/media/uploads', StaticFiles(directory='up'), name='up')\n")
    ctx = Context(AppProfile(base_url="http://x", source_path=str(src)))
    pfx = fu._static_mount_prefixes(ctx)
    assert "/media/uploads" in pfx          # source-detected mount
    assert "/static" in pfx                 # common default


def test_looks_like_id_param():
    assert looks_like_id_param("user_id")
    assert looks_like_id_param("id")
    assert looks_like_id_param("uuid")
    assert not looks_like_id_param("name")
    assert not looks_like_id_param("email")


def test_self_scoped_detection():
    assert a01._is_self_scoped("/users/me")
    assert a01._is_self_scoped("/booking/users/me/manage")
    assert not a01._is_self_scoped("/users/{user_id}")
    assert not a01._is_self_scoped("/admin/users")


def test_public_by_design():
    assert a01._is_public_by_design("/core/auth/login", "login")
    assert a01._is_public_by_design("/openapi.json", "")
    assert not a01._is_public_by_design("/users/", "list_users")


def test_a02_token_in_query_runs_without_authentication():
    """A credential in a query string is visible from the route map alone — the
    check must fire even when Heimdall could not authenticate (no principal)."""
    from heimdall.core.context import Context
    from heimdall.core.model import AppProfile
    from heimdall.discovery import openapi as oa
    from heimdall.modules import a02_crypto_jwt as a02

    spec = {"openapi": "3.1.0", "info": {"title": "T"}, "paths": {
        "/authorize": {"get": {"operationId": "authz", "parameters": [
            {"name": "token", "in": "query", "required": True,
             "schema": {"type": "string"}}]}}}}
    rm = oa.parse_routes(spec)
    ctx = Context(AppProfile(base_url="http://x", routes=rm))   # NO authed principal
    a02._token_in_query(ctx)
    assert any(f.id == "a02-token-in-query" for f in ctx.findings())


def test_business_logic_negative_amount_asymmetric(monkeypatch):
    """A negative accepted+stored in an amount/quantity field is flagged even when
    the POSITIVE is rejected (stock/max cap) — the asymmetric-bound abuse; a
    non-amount field is not (name gate)."""
    from heimdall.modules import business_logic as bl

    class _R:
        def __init__(self, code, js):
            self.status_code, self._js = code, js

        def json(self):
            return self._js

    # base quantity=1 (ok); +1000 rejected (stock cap 400); -1000 accepted, stored
    seq = {1: _R(200, {"quantity": 1}), 1000: _R(400, {"detail": "stock"}),
           -1000: _R(200, {"quantity": -999})}
    monkeypatch.setattr(bl, "_fire", lambda ctx, route, field, value, token: seq[value])

    class _Route:
        method, path, path_params = "POST", "/cart/", []

    out = bl._probe_field(None, _Route(), "quantity", None)
    assert isinstance(out, dict) and "negative_stored" in out      # amount field -> flagged
    assert bl._probe_field(None, _Route(), "score", None) == "unreached"  # name gate


def test_materially_differ_discriminates_boolean_sqli():
    from heimdall.modules import a03_injection as a03

    class R:
        def __init__(self, status, text):
            self.status_code, self.text = status, text

    # reflection: TRUE/FALSE payloads differ by one char -> bodies ~equal -> NOT material
    assert a03._materially_differ(R(200, "x" * 500), R(200, "x" * 501)) is False
    # boolean SQLi: TRUE dumps rows, FALSE empty -> large delta -> material
    assert a03._materially_differ(R(200, "x" * 9000), R(200, "x" * 12)) is True
    # a status-class change is also material
    assert a03._materially_differ(R(200, "ok"), R(500, "ok")) is True


def _sast_scan(sast, src):
    """Run the SAST scan over a source dir and return {kind: [(loc, code), ...]}."""
    graph = {"sinks": [], "handlers": {}, "calls": {}}
    for p in sast._iter_py(str(src)):
        sast._scan_file(p, "f.py", open(p).readlines(), graph)
    out = {}
    for s in graph["sinks"]:
        out.setdefault(s["kind"], []).append((s["loc"], s["code"]))
    return out, graph


def _sast_full_scan(sast, src):
    """Mirror run()'s pre-pass: collect cross-file auth aliases + router-graph
    auth before scanning, so multi-file auth patterns resolve correctly."""
    import ast
    import os
    root = str(src)
    graph = {"sinks": [], "handlers": {}, "calls": {}, "auth_aliases": set()}
    top_pkg = os.path.basename(root.rstrip("/"))
    files = list(sast._iter_py(root))
    parsed = []
    for p in files:
        try:
            tree = ast.parse(open(p).read(), filename=p)
        except (SyntaxError, ValueError):
            continue
        sast._collect_auth_aliases(tree, graph["auth_aliases"])
        parsed.append((sast._module_key(os.path.relpath(p, root)), tree))
    graph["protected_routers"] = sast._resolve_protected_routers(parsed, top_pkg)
    graph["auth_controllers"] = sast._resolve_auth_controllers(parsed)
    graph["app_auth_middleware"] = sast._has_auth_middleware(parsed)
    for p in files:
        sast._scan_file(p, os.path.relpath(p, root), open(p).readlines(), graph)
    out = {}
    for s in graph["sinks"]:
        out.setdefault(s["kind"], []).append((s["loc"], s["code"]))
    return out, graph


def test_sast_detects_sinks_and_suppresses_public(tmp_path):
    from heimdall.modules import sast

    src = tmp_path / "app"
    (src / "svc").mkdir(parents=True)
    (src / "svc" / "vuln.py").write_text(
        "import subprocess, requests\n"
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "def run_cmd(p):\n"
        "    return subprocess.run('df -h ' + p, shell=True)\n"          # cmdi
        "def fetch(url):\n"
        "    return requests.get(url)\n"                                  # ssrf
        "@router.delete('/widgets/{id}')\n"
        "def delete_widget(id):\n"                                        # noauth (state-change, no Depends)
        "    ...\n"
        "@router.post('/register')\n"
        "def register(body):\n"                                          # public -> suppressed
        "    ...\n"
        "@router.delete('/items/{id}')\n"
        "def delete_item(id, user=Depends(get_current_user)):\n"          # has auth -> not flagged
        "    ...\n"
        "# auth=Depends(RolesBasedAuthChecker([ADMIN]))\n"               # commented-out auth
    )
    hits, _ = _sast_scan(sast, src)

    assert len(hits.get("cmdi", [])) == 1
    assert len(hits.get("ssrf", [])) == 1
    assert len(hits.get("commented_auth", [])) == 1
    noauth_paths = [c for _, c in hits.get("noauth", [])]
    assert any("/widgets/{id}" in c for c in noauth_paths)          # flagged
    assert not any("/register" in c for c in noauth_paths)          # public -> suppressed
    assert not any("/items/{id}" in c for c in noauth_paths)        # has Depends -> not flagged


def test_sast_no_false_positive_on_prose_and_literals(tmp_path):
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "clean.py").write_text(
        "import subprocess, requests\n"
        "# This function uses Depends(...) for authentication, see docs.\n"   # prose, not a sink
        "def ok():\n"
        "    subprocess.run(['ls', '-l'])\n"                                   # list form, no shell
        "    requests.get('https://api.example.com/health')\n"                # constant URL
        "    return 1\n"
    )
    hits, _ = _sast_scan(sast, src)
    assert hits == {}


def test_sast_decorator_level_auth_suppresses_noauth(tmp_path):
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "r.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "@router.put('/{slug}', dependencies=[Depends(check_article_modification_permissions)])\n"
        "def update(article):\n"
        "    ...\n"
    )
    hits, _ = _sast_scan(sast, src)
    # auth declared at the decorator level -> NOT a missing-auth finding
    assert "noauth" not in hits


def test_sast_annotated_alias_dep_suppresses_noauth(tmp_path):
    """`current_user: CurrentUser` where CurrentUser = Annotated[User, Depends(...)]
    is authenticated — the idiomatic FastAPI DI pattern (official template)."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "r.py").write_text(
        "from typing import Annotated\n"
        "from fastapi import APIRouter, Depends\n"
        "CurrentUser = Annotated[object, Depends(get_current_user)]\n"
        "router = APIRouter()\n"
        "@router.delete('/items/{id}')\n"
        "def delete_item(id, current_user: CurrentUser):\n"   # authed via alias
        "    ...\n"
        "@router.delete('/widgets/{id}')\n"
        "def delete_widget(id):\n"                            # genuinely no auth
        "    ...\n"
    )
    hits, _ = _sast_scan(sast, src)
    noauth = [c for _, c in hits.get("noauth", [])]
    assert not any("/items/{id}" in c for c in noauth)   # alias -> authed -> suppressed
    assert any("/widgets/{id}" in c for c in noauth)     # no dep -> still flagged


def test_sast_text_fallback_recovers_alias_from_unparseable():
    """When a file won't ast.parse (target on a newer Python), auth aliases are
    still recovered from raw text so routes aren't falsely flagged no-auth."""
    from heimdall.modules import sast

    # `except A, B:` is a SyntaxError on the analyzer's Python 3.12
    src = (
        "def get_current_user(session, token):\n"
        "    try:\n"
        "        payload = decode(token)\n"
        "    except InvalidTokenError, ValidationError:\n"
        "        raise\n"
        "CurrentUser = Annotated[User, Depends(get_current_user)]\n"
        "SessionDep = Annotated[Session, Depends(get_db)]\n"   # not auth -> ignored
    )
    import ast
    try:
        ast.parse(src)
        assert False, "expected this source to be unparseable on py3.12"
    except SyntaxError:
        pass
    aliases = set()
    sast._collect_auth_aliases_text(src, aliases)
    assert "CurrentUser" in aliases        # auth alias recovered by text
    assert "SessionDep" not in aliases      # non-auth Depends not treated as auth


def test_sast_ssti_file_read_template_not_flagged(tmp_path):
    """Template compiled from a file read on disk is trusted, not SSTI; a template
    built from a request value still is."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "email.py").write_text(
        "from pathlib import Path\n"
        "from jinja2 import Template\n"
        "def render(name, context):\n"
        "    template_str = (Path(__file__).parent / name).read_text()\n"
        "    return Template(template_str).render(context)\n"       # trusted file
        "def render_bad(user_supplied, context):\n"
        "    return Template(user_supplied).render(context)\n"       # real SSTI
    )
    hits, _ = _sast_scan(sast, src)
    ssti_codes = [c for _, c in hits.get("ssti", [])]
    assert len(ssti_codes) == 1
    assert any("user_supplied" in c for c in ssti_codes)


def test_sast_router_composition_auth_suppresses_noauth(tmp_path):
    """Auth applied once at router assembly — `include_router(child,
    dependencies=[Depends(get_current_user)])` — protects every route on the
    child router even though no handler declares its own dep (Netflix/dispatch)."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    (src / "entity").mkdir(parents=True)
    (src / "entity" / "views.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('')\n"
        "def create_entity(body):\n"          # no per-handler dep...
        "    ...\n"
        "@router.delete('/{entity_id}')\n"
        "def delete_entity(entity_id):\n"
        "    ...\n"
    )
    (src / "api.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from app.entity.views import router as entity_router\n"
        "api_router = APIRouter()\n"
        "authed = APIRouter()\n"
        "authed.include_router(entity_router, prefix='/entities')\n"
        "api_router.include_router(authed, dependencies=[Depends(get_current_user)])\n"
    )
    hits, graph = _sast_full_scan(sast, src)
    assert ("entity.views", "router") in graph["protected_routers"]
    assert "noauth" not in hits          # ...protected via composition


def test_sast_webhook_signature_verification_suppresses_noauth(tmp_path):
    """A handler that verifies an inbound request signature (webhook HMAC) is
    authenticated even with no Depends."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "hooks.py").write_text(
        "from fastapi import APIRouter, Request\n"
        "from slack_sdk.signature import SignatureVerifier\n"
        "router = APIRouter()\n"
        "def _ok(body, headers):\n"
        "    return SignatureVerifier('s').is_valid_request(body, headers)\n"
        "@router.post('/slack/event')\n"
        "def slack_event(request: Request):\n"
        "    ...\n"
    )
    hits, _ = _sast_full_scan(sast, src)
    assert "noauth" not in hits


def test_sast_ssti_trusted_sources_not_flagged(tmp_path):
    """Module constants and static config dicts are trusted templates; request-
    derived or built strings are SSTI."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "t.py").write_text(
        "from jinja2 import Template, Environment\n"
        "SUMMARY_TEMPLATE = 'Hi {{ name }}'\n"
        "env = Environment()\n"
        "def render_const(ctx):\n"
        "    return Template(SUMMARY_TEMPLATE).render(ctx)\n"          # const -> trusted
        "def render_cfg(cfg, ctx):\n"
        "    return env.from_string(cfg['header']).render(ctx)\n"       # config dict -> trusted
        "def render_user(request, ctx):\n"
        "    return Template(request['tpl']).render(ctx)\n"            # request -> SSTI
        "def render_built(name, ctx):\n"
        "    return Template('Hi ' + name).render(ctx)\n"              # built -> SSTI
    )
    hits, _ = _sast_full_scan(sast, src)
    codes = [c for _, c in hits.get("ssti", [])]
    assert len(codes) == 2
    assert any("request['tpl']" in c for c in codes)
    assert any("'Hi ' + name" in c for c in codes)


def test_sast_ssrf_constant_url_not_flagged(tmp_path):
    """A config/constant URL is not attacker-influenceable — not SSRF; a
    variable URL is a lead."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "clients.py").write_text(
        "import requests\n"
        "JWKS_URL = 'https://issuer/.well-known/jwks.json'\n"
        "def keys():\n"
        "    return requests.get(JWKS_URL).json()\n"                  # const -> not SSRF
        "def fetch(url):\n"
        "    return requests.get(url)\n"                              # variable -> lead
    )
    hits, _ = _sast_full_scan(sast, src)
    codes = [c for _, c in hits.get("ssrf", [])]
    assert not any("JWKS_URL" in c for c in codes)
    assert any("requests.get(url)" in c for c in codes)


def test_sast_skips_migration_dirs(tmp_path):
    """Alembic revision/version DDL is offline, not a web-reachable SQLi sink."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    (src / "revisions" / "versions").mkdir(parents=True)
    (src / "revisions" / "versions" / "0001_x.py").write_text(
        "def upgrade():\n"
        "    conn.execute(f\"update t set s = '{r[1]}' where id = {r[0]}\")\n"
    )
    scanned = [p for p in sast._iter_py(str(src))]
    assert scanned == []                 # whole revisions subtree skipped


def test_sast_auth_ish_recognizes_fastapi_users_and_rejects_false_friends():
    """Real-world auth dependency names — including fastapi-users' role-qualified
    current_<role>_user — are recognized; CRUD/lookup names are not."""
    from heimdall.modules import sast

    for name in ("current_user", "current_active_user", "current_admin_user",
                 "current_curator_or_admin_user", "current_limited_user",
                 "current_chat_accessible_user", "require_permission", "verify_jwt",
                 "user_api_key_auth", "get_admin_user", "authorize"):
        assert sast._auth_ish(name), name
    for name in ("get_author", "authors_list", "create_user", "delete_user",
                 "get_user_by_id", "update_user", "list_users", "get_book"):
        assert not sast._auth_ish(name), name


def test_sast_auth_router_subclass_and_cbv_controller(tmp_path):
    """Mealie-style auth: an APIRouter SUBCLASS that bakes the auth dep into its
    constructor, and a class-based-view controller whose base class carries the
    auth dep as a class attribute — both authenticate their routes."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "routers.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "class UserAPIRouter(APIRouter):\n"
        "    def __init__(self, **kw):\n"
        "        super().__init__(dependencies=[Depends(get_current_user)], **kw)\n"
    )
    (src / "base.py").write_text(
        "from fastapi import Depends\n"
        "class BaseUserController:\n"
        "    user = Depends(get_current_user)\n"        # CBV class-attr auth
        "class BasePublicController:\n"
        "    pass\n"                                     # no auth
    )
    (src / "routes.py").write_text(
        "from routers import UserAPIRouter\n"
        "from fastapi import APIRouter\n"
        "from base import BaseUserController, BasePublicController\n"
        "srouter = UserAPIRouter(prefix='/s')\n"
        "@srouter.post('')\n"
        "def create_s(data): ...\n"                      # authed via subclass router
        "prouter = APIRouter(prefix='/p')\n"
        "@controller(prouter)\n"
        "class SecureCtl(BaseUserController):\n"
        "    @prouter.delete('/{id}')\n"
        "    def remove(self, id): ...\n"                # authed via CBV base class
        "orouter = APIRouter(prefix='/o')\n"
        "@controller(orouter)\n"
        "class OpenCtl(BasePublicController):\n"
        "    @orouter.post('/act')\n"
        "    def act(self, data): ...\n"                 # public controller -> flagged
    )
    hits, _ = _sast_full_scan(sast, src)
    noauth = [c for _, c in hits.get("noauth", [])]
    assert not any("/s" in c and "create_s" in c for c in noauth)   # subclass router
    assert not any("remove" in c for c in noauth)                   # CBV base auth
    assert any("act" in c for c in noauth)                          # public ctl flagged


def test_sast_sql_fstring_trusted_interpolation(tmp_path):
    """f-string SQL interpolating only trusted identifiers (attributes, consts,
    trusted locals) is not SQLi; a request-derived value is."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "q.py").write_text(
        "from sqlalchemy import text\n"
        "def a(session, cls):\n"
        "    session.execute(text(f'SET x = {cls._threshold}'))\n"          # attr -> safe
        "def b(session, Model):\n"
        "    session.execute(text(f'SELECT id FROM {Model.__tablename__}'))\n"  # dunder -> safe
        "def c(session):\n"
        "    state = self._fk or 'origin'\n"
        "    session.execute(text(f'SET role = {state}'))\n"                # trusted local
        "def d(session, request):\n"
        "    name = request['q']\n"
        "    session.execute(text(f\"SELECT * FROM t WHERE n = '{name}'\"))\n"  # tainted!
    )
    hits, _ = _sast_full_scan(sast, src)
    sqli = [c for _, c in hits.get("sqli", [])]
    assert len(sqli) == 1
    assert "WHERE n" in sqli[0]


def test_sast_auth_edge_cases_security_alias_appdeps_concat(tmp_path):
    """More adversarial auth: Security() inside an Annotated alias, a global
    FastAPI(dependencies=[auth]), and a concatenated deps list — all authed; the
    non-auth equivalents still flag."""
    from heimdall.modules import sast

    # Security() in an Annotated alias
    a = tmp_path / "a"
    a.mkdir()
    (a / "m.py").write_text(
        "from typing import Annotated\n"
        "from fastapi import FastAPI, Security\n"
        "Admin = Annotated[object, Security(oauth2)]\n"
        "app = FastAPI()\n"
        "@app.post('/x')\n"
        "def h(u: Admin): ...\n")
    assert "noauth" not in _sast_full_scan(sast, a)[0]

    # global FastAPI(dependencies=[auth]) + concatenated auth deps var
    b = tmp_path / "b"
    b.mkdir()
    (b / "m.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI(dependencies=[Depends(get_current_user)])\n"
        "@app.post('/x')\n"
        "def h(body): ...\n")
    assert "noauth" not in _sast_full_scan(sast, b)[0]

    # control: FastAPI(dependencies=[non-auth]) still flags
    c = tmp_path / "c"
    c.mkdir()
    (c / "m.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI(dependencies=[Depends(get_db)])\n"
        "@app.post('/x')\n"
        "def h(body): ...\n")
    assert any("/x" in code for _, code in _sast_full_scan(sast, c)[0].get("noauth", []))


def test_sast_auth_edge_cases_partial_realias_depsvar(tmp_path):
    """Adversarial auth patterns: partial(auth_fn), an alias-of-an-alias, and a
    dependencies=<variable> list — all authenticated; a non-auth deps variable
    still flags."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "r.py").write_text(
        "from typing import Annotated\n"
        "from functools import partial\n"
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "A = Annotated[object, Depends(get_current_user)]\n"
        "B = A\n"                                         # alias-of-alias
        "protected = [Depends(get_current_user)]\n"       # auth deps variable
        "just_db = [Depends(get_db)]\n"                   # NON-auth deps variable
        "@router.post('/p')\n"
        "def a(u=Depends(partial(require_role, 'admin'))): ...\n"   # partial(auth)
        "@router.post('/re')\n"
        "def b(u: B): ...\n"                              # alias-of-alias annotation
        "@router.post('/dv', dependencies=protected)\n"
        "def c(): ...\n"                                  # deps=<auth var>
        "@router.post('/open', dependencies=just_db)\n"
        "def d(body): ...\n"                             # deps=<non-auth var> -> flagged
    )
    hits, _ = _sast_full_scan(sast, src)
    noauth = [c for _, c in hits.get("noauth", [])]
    assert not any(p in c for c in noauth for p in ("/p", "/re", "/dv"))
    assert any("/open" in c for c in noauth)             # non-auth deps var still flags


def test_sast_decorator_auth_login_required(tmp_path):
    """Flask-Login / Starlette-style auth decorators (@login_required,
    @roles_required, @requires) guard a route even with no Depends in the sig."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "r.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "@app.post('/items')\n"
        "@login_required\n"
        "def create(request): ...\n"                 # decorator auth
        "@app.delete('/w/{id}')\n"
        "@roles_required('admin')\n"
        "def rm(request, id): ...\n"                  # decorator auth
        "@app.post('/open')\n"
        "def open_ep(body): ...\n"                    # no auth -> flagged
    )
    hits, _ = _sast_full_scan(sast, src)
    noauth = [c for _, c in hits.get("noauth", [])]
    assert not any("/items" in c for c in noauth)
    assert not any("/w/{id}" in c for c in noauth)
    assert any("/open" in c for c in noauth)


def test_cookie_session_login_detection():
    """A login cookie set on a 302 (in the session jar after the redirect) is
    detected as the credential, auth_kind flips to cookie, and the jar is cleared
    so it doesn't pollute unauthenticated probes."""
    import requests

    from heimdall.bootstrap.principals import _session_cookie
    from heimdall.core.model import AppProfile

    class _R:
        cookies = requests.cookies.RequestsCookieJar()
        history: list = []

    class _H:
        s = requests.Session()

    h = _H()
    h.s.cookies.set("fastapi_auth", "abc123")     # landed in the jar after the 302
    p = AppProfile(base_url="http://x")
    val = _session_cookie(p, _R(), h)
    assert val == "abc123"
    assert p.auth.auth_kind == "cookie"
    assert p.auth.credential_name == "fastapi_auth"
    assert len(h.s.cookies) == 0                    # jar cleared


def test_sast_auth_middleware_guards_routes(tmp_path):
    """An app-wide authentication middleware guards every route (routes read
    request.state.user, no Depends) — no-auth must not fire. Without it, the same
    mutating route IS flagged."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "main.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "app.add_middleware(JWTAuthenticationMiddleware, backend=b, exclude_urls=['/login'])\n"
        "@app.post('/items')\n"
        "def create_item(request: Request): ...\n"       # middleware-guarded
    )
    hits, _ = _sast_full_scan(sast, src)
    assert "noauth" not in hits

    (src / "main.py").write_text(                         # control: no auth middleware
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "app.add_middleware(GZipMiddleware)\n"            # a non-auth middleware
        "@app.post('/items')\n"
        "def create_item(body): ...\n"
    )
    hits2, _ = _sast_full_scan(sast, src)
    assert any("/items" in c for _, c in hits2.get("noauth", []))


def test_sast_security_dependency_and_registration_public(tmp_path):
    """FastAPI `Security(...)` is an auth dependency (used for JWT/OAuth), and
    `user_registration` is public-by-design (registration)."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "r.py").write_text(
        "from fastapi import APIRouter, Security\n"
        "router = APIRouter()\n"
        "@router.delete('')\n"
        "def delete_user(auth=Security(access_security)): ...\n"   # Security() -> authed
        "@router.post('')\n"
        "def user_registration(body): ...\n"                       # registration -> public
        "@router.post('/widgets')\n"
        "def make_widget(body): ...\n"                             # genuinely no auth
    )
    hits, _ = _sast_full_scan(sast, src)
    noauth = [c for _, c in hits.get("noauth", [])]
    assert not any("delete_user" in c for c in noauth)          # Security() recognized
    assert not any("user_registration" in c for c in noauth)    # registration public
    assert any("make_widget" in c for c in noauth)              # still flagged


def test_sast_keyword_path_and_router_include(tmp_path):
    """`@router.delete(path="/{id}")` and `include_router(router=child,
    dependencies=[Depends(auth)])` use keyword args — the path must be read and
    the keyword-child auth must propagate."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "r.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "child = APIRouter()\n"
        "@child.delete(path='/{id}')\n"
        "def remove(id): ...\n"                       # authed via keyword-child include
        "pub = APIRouter()\n"
        "@pub.delete(path='/{id}')\n"
        "def remove_pub(id): ...\n"                   # not protected -> flagged
        "parent = APIRouter()\n"
        "parent.include_router(router=child, dependencies=[Depends(current_user)])\n"
    )
    hits, _ = _sast_full_scan(sast, src)
    codes = [c for _, c in hits.get("noauth", [])]
    assert any("remove_pub" in c and "/{id}" in c for c in codes)   # keyword path read
    assert not any("(remove)" in c for c in codes)                  # keyword-child auth


def test_sast_public_auth_account_routes_suppressed(tmp_path):
    """Auth/account-lifecycle endpoints (login/token/session, registration,
    password flows) are unauthenticated by design — not missing-auth findings."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "r.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/auth')\n"
        "def auth_cookie_session_user(body): ...\n"              # login
        "@router.post('/users/auth')\n"
        "def get_user_auth_token(body): ...\n"                   # token
        "@router.post('')\n"
        "def create_user(body): ...\n"                           # registration
        "@router.post('/passwords/request-change')\n"
        "def request_change_user_password(body): ...\n"          # password flow
        "@router.delete('/widgets/{id}')\n"
        "def delete_widget(id): ...\n"                           # genuinely no auth
    )
    hits, _ = _sast_full_scan(sast, src)
    noauth = [c for _, c in hits.get("noauth", [])]
    assert not any("/auth" in c for c in noauth)
    assert not any("create_user" in c for c in noauth)
    assert not any("request-change" in c for c in noauth)
    assert any("/widgets/{id}" in c for c in noauth)            # still flagged


def test_sast_flags_state_changing_get(tmp_path):
    """A GET/HEAD handler that performs a DB mutation (delete/commit) is a
    state-changing safe-method route — CSRF-able; read-only GETs are not."""
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    (src / "m.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/books/{id}/delete')\n"
        "def delete_book(id, db):\n"
        "    db.delete(book)\n"                       # mutation over GET
        "    db.commit()\n"
        "    return 1\n"
        "@router.get('/books/{id}')\n"
        "def read_book(id, db):\n"
        "    return db.query(Book).get(id)\n"         # read-only GET
        "@router.get('/metrics')\n"
        "def metrics():\n"
        "    seen = set()\n"
        "    seen.add(1)\n"                           # set.add -> NOT a DB write
        "    return list(seen)\n"
        "@router.get('/new')\n"
        "def new_form(request):\n"
        "    return render('form.html')\n"            # pure render
    )
    hits, _ = _sast_full_scan(sast, src)
    codes = [c for _, c in hits.get("state_change_get", [])]
    assert len(codes) == 1                            # only the real DB mutation
    assert "/books/{id}/delete" in codes[0]


def test_a07_register_enumeration(monkeypatch):
    """Registration that answers differently for an existing vs a fresh email is
    an enumeration oracle; a uniform generic response is not."""
    from heimdall.core.context import Context
    from heimdall.core.model import AppProfile
    from heimdall.modules import a07_auth as a07

    class _Resp:
        def __init__(self, code, text=""):
            self.status_code, self.text = code, text

    class _P:
        email = "known@example.com"

    def _wire(ctx, responder):
        ctx.auth.register_path = "/auth/register"
        monkeypatch.setattr(ctx, "principal", lambda *a, **k: _P())
        monkeypatch.setattr(ctx, "post", responder)

    # oracle: existing email -> 400 "already registered", fresh -> 201
    ctx = Context(AppProfile(base_url="http://x"))
    seen = set()
    def leak(path, json=None, data=None, **k):
        email = (json or data or {}).get("email", "")
        if email in seen:                    # second time this email is seen -> "exists"
            return _Resp(400, '{"detail":"Email already registered"}')
        seen.add(email)
        return _Resp(201, '{"id":9}')
    _wire(ctx, leak)
    a07._register_enum(ctx)
    fs = [f for f in ctx.findings() if f.id == "a07-register-user-enum"]
    assert fs and fs[0].severity.upper() == "LOW"

    # no oracle: identical generic 200 for both
    ctx2 = Context(AppProfile(base_url="http://x"))
    _wire(ctx2, lambda *a, **k: _Resp(200, '{"status":"ok"}'))
    a07._register_enum(ctx2)
    fs2 = [f for f in ctx2.findings() if f.id == "a07-register-user-enum"]
    assert fs2 and fs2[0].severity.upper() == "SAFE"


def test_a07_skips_rate_limit_when_no_credential_evaluation(monkeypatch):
    """All-422 responses mean the endpoint never processed a login (or discovery
    mis-identified a CRUD route as login) — don't report a missing throttle."""
    from heimdall.core.context import Context
    from heimdall.core.model import AppProfile
    from heimdall.modules import a07_auth as a07

    class _Resp:
        def __init__(self, code):
            self.status_code = code

    ctx = Context(AppProfile(base_url="http://x"))
    ctx.auth.login_path = "/books"

    # not a login: every attempt is a schema 422, credentials never evaluated
    monkeypatch.setattr(a07, "_login_attempt", lambda *a, **k: _Resp(422))
    a07._brute_force(ctx)
    assert not any(f.id == "a07-login-rate-limit" for f in ctx.findings())

    # a real login rejecting bogus creds (401) with no 429 -> finding fires
    ctx2 = Context(AppProfile(base_url="http://x"))
    ctx2.auth.login_path = "/auth/login"
    monkeypatch.setattr(a07, "_login_attempt", lambda *a, **k: _Resp(401))
    a07._brute_force(ctx2)
    assert any(f.id == "a07-login-rate-limit" for f in ctx2.findings())


def test_race_excludes_delete_from_candidates():
    """DELETE is not a race target: its 'sequential repeat rejected' signal is
    trivially true (resource gone) and duplicate-delete has no double-spend."""
    import inspect

    from heimdall.modules import race_conditions
    src = inspect.getsource(race_conditions.run)
    # the candidate verb tuple must not include DELETE
    assert '"POST", "PUT", "PATCH"' in src
    assert '"DELETE"' not in src.split("candidates = [")[1].split("]")[0]


def test_sast_callgraph_resolves_sink_to_handler_route(tmp_path):
    from heimdall.modules import sast

    src = tmp_path / "app"
    src.mkdir()
    # sink lives in a util; the route handler reaches it 1 hop away
    (src / "a.py").write_text(
        "import subprocess\n"
        "def run_df(p):\n"
        "    return subprocess.run('df -h ' + p, shell=True)\n"          # cmdi sink in util
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "@router.get('/admin/disk')\n"
        "def disk(parameters, user=Depends(get_current_user)):\n"
        "    return run_df(parameters)\n"                                 # handler calls the util
    )
    _hits, graph = _sast_scan(sast, src)
    cmdi = [s for s in graph["sinks"] if s["kind"] == "cmdi"]
    assert len(cmdi) == 1
    routes = sast._routes_for_sink(cmdi[0], graph["handlers"], graph["calls"])
    assert ("get", "/admin/disk") in routes         # resolved util sink -> its handler route


def test_sast_escalation_tokens_forge_elevated_claims():
    import jwt as pyjwt
    from heimdall.core.context import Context
    from heimdall.core.model import AppProfile
    from heimdall.discovery import auth as auth_detect
    from heimdall.modules import sast

    base = pyjwt.encode({"sub": "alice", "role": "user"}, "k", algorithm="HS256")
    ctx = Context(AppProfile(base_url="http://x"))
    toks = sast._escalation_tokens(ctx, base)
    assert toks, "expected forged escalation tokens"
    # at least one forged token decodes to an elevated role (alg:none, unverified)
    elevated = []
    for tok, _how in toks:
        dec = auth_detect.decode_jwt(tok)
        if dec and dec[1].get("role") in ("admin", "super_admin"):
            elevated.append(dec[1]["role"])
    assert "admin" in elevated
    assert any("alg:none" in how for _t, how in toks)


def test_sast_urlish_param_matching():
    from heimdall.modules import sast
    assert sast._URLISH.search("image_url")
    assert sast._URLISH.search("callback")
    assert sast._URLISH.search("avatar")
    assert not sast._URLISH.search("quantity")
    assert not sast._URLISH.search("email")


def test_sast_canary_records_fetch():
    import urllib.request
    from heimdall.modules import sast

    with sast._Canary() as c:
        urllib.request.urlopen(f"http://127.0.0.1:{c.port}/heimdall-ssrf", timeout=3).read()
        import time
        time.sleep(0.2)
        assert c.hits and "/heimdall-ssrf" in c.hits[0]
