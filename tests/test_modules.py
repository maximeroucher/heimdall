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
