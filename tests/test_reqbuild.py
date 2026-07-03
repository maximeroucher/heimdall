"""Schema-driven request builder: FK detection + scalar synthesis."""

from heimdall.core import reqbuild


def test_looks_fk():
    assert reqbuild._looks_fk("pack_id")
    assert reqbuild._looks_fk("user_uuid")
    assert not reqbuild._looks_fk("id")        # own id, not a foreign key
    assert not reqbuild._looks_fk("quantity")
    assert not reqbuild._looks_fk("name")


def test_synth_scalars_by_type_and_format():
    s = lambda schema, name: reqbuild._synth(None, schema, None, name, "/x")
    assert s({"type": "integer"}, "quantity") == 1
    assert s({"type": "number"}, "price") == 1.0
    assert s({"type": "boolean"}, "flag") is True
    assert s({"type": "string"}, "title") == "heimdall"
    assert s({"type": "string", "format": "email"}, "mail") == "heimdall@example.com"
    assert s({"type": "string", "format": "uuid"}, "ref").count("-") == 4
    assert s({"type": "string", "format": "date"}, "day") == "2026-01-01"
    assert s({"enum": ["a", "b"]}, "choice") == "a"
    assert s({"type": "array", "items": {"type": "string"}}, "tags") == ["heimdall"]


def test_synth_unwraps_optional_anyof():
    # Optional field: anyOf[string, null] -> pick the non-null branch.
    v = reqbuild._synth(None, {"anyOf": [{"type": "string"}, {"type": "null"}]}, None, "note", "/x")
    assert v == "heimdall"
