"""Module registry + small module helpers."""

from heimdall.modules import a01_access_control as a01
from heimdall.modules.base import looks_like_id_param


def test_all_modules_register():
    from heimdall.modules.base import REGISTRY, ordered
    from heimdall.runner import _import_all_modules
    _import_all_modules()
    keys = {m.key for m in ordered()}
    for expected in ("a01", "a02", "a03", "a05", "a06", "a07", "a10", "csrf", "race", "session"):
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
