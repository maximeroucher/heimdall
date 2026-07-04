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
    hits = {}
    for p in sast._iter_py(str(src)):
        lines = open(p).readlines()
        sast._scan_file(p, "vuln.py", lines, hits)

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
    hits = {}
    for p in sast._iter_py(str(src)):
        sast._scan_file(p, "clean.py", open(p).readlines(), hits)
    assert hits == {}
