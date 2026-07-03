"""Build a *valid* request for a route from its OpenAPI schema + live responses.

Many deep code paths are unreachable with an empty body — the endpoint 422s
before its logic runs. This builder turns "what the route requires" (path params
+ typed/required body fields) into concrete values:

  * scalars are synthesised by type/format (string/int/bool/uuid/email/date/enum),
  * id / foreign-key fields are resolved from a RELATED endpoint's response (the
    producer→consumer link — e.g. a ``pack_id`` body/path field is filled from
    ``GET /tombola/pack_tickets``), so the request references a real object.

Shared by the race / injection / write-BOLA modules so their probes reach the
handler instead of bouncing off validation. Best-effort: unknown shapes fall
back to a benign placeholder.
"""

from __future__ import annotations

from .context import Context

_FK_SUFFIXES = ("_id", "_uuid", "_pk")
_FK_WORDS = ("id", "uuid")


def _looks_fk(name: str) -> bool:
    n = (name or "").lower()
    return n != "id" and (n.endswith(_FK_SUFFIXES) or any(n.endswith(w) for w in _FK_WORDS))


def _synth_scalar(name: str) -> str:
    return "1" if _looks_fk(name) else "heimdall"


def build_request(ctx: Context, route, token: str | None, principal=None, overrides=None):
    """Return (filled_path, body) — a best-effort valid request for ``route``.

    ``overrides`` (a dict) replaces specific body fields after synthesis — used
    by the injection modules to drop a payload into one field while the rest of
    the body stays valid, so the request passes validation and reaches the sink.
    """
    vals = {}
    for p in route.path_params:
        if principal and principal.user_id and "user" in p.lower():
            vals[p] = principal.user_id
        else:
            vals[p] = harvest_id(ctx, p, token, route.path) or _synth_scalar(p)
    path = route.fill_path(vals)
    body = _build_body(ctx, route, token) if route.body_schema else {}
    if overrides:
        body.update(overrides)
    return path, body


def string_body_fields(route) -> list[str]:
    """Names of string-typed body fields — the injectable ones."""
    schema = route.body_schema or {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    out = []
    for name, s in props.items():
        if not isinstance(s, dict) or s.get("enum"):
            continue
        t = s.get("type")
        if t == "string" or (t is None and "format" not in s):
            out.append(name)
    return out


def _build_body(ctx: Context, route, token: str | None) -> dict:
    schema = route.body_schema or {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        # allOf/anyOf/oneOf wrapper
        for comb in ("allOf", "anyOf", "oneOf"):
            for sub in schema.get(comb, []):
                if isinstance(sub, dict) and isinstance(sub.get("properties"), dict):
                    props, schema = sub["properties"], sub
                    break
    if not isinstance(props, dict):
        return {}
    required = schema.get("required")
    names = required if isinstance(required, list) and required else list(props.keys())
    return {n: _synth(ctx, props.get(n, {}), token, n, route.path) for n in names}


def _synth(ctx: Context, schema, token, name: str, hint_path: str):
    if not isinstance(schema, dict):
        return "heimdall"
    if schema.get("enum"):
        return schema["enum"][0]
    for comb in ("anyOf", "oneOf", "allOf"):
        opts = schema.get(comb)
        if isinstance(opts, list) and opts:
            # prefer a non-null branch
            branch = next((o for o in opts if isinstance(o, dict)
                           and o.get("type") != "null"), opts[0])
            return _synth(ctx, branch, token, name, hint_path)
    if _looks_fk(name):
        hid = harvest_id(ctx, name, token, hint_path)
        if hid:
            return hid
    t, fmt = schema.get("type"), schema.get("format")
    if t in (None, "string"):
        if fmt == "email":
            return "heimdall@example.com"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000001"
        if fmt == "date-time":
            return "2026-01-01T00:00:00Z"
        if fmt == "date":
            return "2026-01-01"
        return "heimdall"
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return True
    if t == "array":
        items = schema.get("items")
        return [_synth(ctx, items, token, name, hint_path)] if isinstance(items, dict) else []
    if t == "object":
        props = schema.get("properties") or {}
        req = schema.get("required") or []
        return {n: _synth(ctx, props.get(n, {}), token, n, hint_path) for n in req}
    return "heimdall"


def harvest_id(ctx: Context, name: str, token: str | None, hint_path: str) -> str | None:
    """Resolve an id/FK value from a related GET list endpoint's live response
    (the producer→consumer link). Matched by the field's resource word and path
    segments shared with ``hint_path``."""
    resource = name.lower()
    for sfx in _FK_SUFFIXES:
        resource = resource.removesuffix(sfx)
    resource = resource.rstrip("_") or name.lower()
    segs = [s for s in hint_path.lower().split("/") if s and "{" not in s]
    lists = [r for r in ctx.routes.by_method("GET")
             if not r.has_path_param
             and ((resource and resource in r.path.lower())
                  or any(s in r.path.lower() for s in segs))]
    lists.sort(key=lambda r: -len(set(r.path.lower().split("/")) & set(segs)))
    for lr in lists[:6]:
        try:
            resp = ctx.get(lr.path, token=token)
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code >= 300:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        items = data.get("items", data) if isinstance(data, dict) else data
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and it.get("id"):
                    return str(it["id"])
    return None
