"""Fetch and parse the target's OpenAPI document into a ``RouteMap``.

Every FastAPI app serves ``/openapi.json`` (unless explicitly disabled), which
is the single richest black-box source: every path, method, required auth,
path/query params and request-body schema. This is the backbone of discovery —
modules read routes off here rather than hard-coding paths.
"""

from __future__ import annotations

import re
from typing import Any

import requests

from ..core.model import Route, RouteMap

# Common locations FastAPI/other frameworks expose the schema at. Apps routinely
# version the API (openapi_url="/v1/openapi.json"), so cover the version prefixes.
OPENAPI_CANDIDATES = [
    "/openapi.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/docs/openapi.json",
    "/swagger.json",
    "/v3/api-docs",  # springdoc, in case a proxy fronts something else
]

DOC_CANDIDATES = ["/docs", "/redoc", "/swagger", "/api/docs"]
# Docs pages we scrape as a last resort to learn a CUSTOM openapi_url — the
# Swagger/ReDoc HTML references it (url: '…/openapi.json' / spec-url="…").
_DOCS_TO_SCRAPE = ["/docs", "/v1/docs", "/v2/docs", "/api/docs", "/api/v1/docs",
                   "/redoc", "/v1/redoc", "/swagger", "/swagger-ui"]
_OPENAPI_HREF_RE = re.compile(r"""["']([^"'\s]*openapi[^"'\s]*\.json)["']""", re.IGNORECASE)


def _try_spec(base: str, path: str, timeout: float) -> tuple[str, dict] | None:
    try:
        r = requests.get(f"{base}{path}", timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
        try:
            spec = r.json()
        except ValueError:
            return None
        if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec):
            return path, spec
    return None


def fetch_openapi(base_url: str, timeout: float = 15.0) -> tuple[str, dict] | None:
    """Return ``(path, spec)`` for the first reachable OpenAPI doc, else None."""
    base = base_url.rstrip("/")
    for path in OPENAPI_CANDIDATES:
        hit = _try_spec(base, path, timeout)
        if hit:
            return hit
    # Fallback: scrape a docs page for a custom openapi_url (e.g. "/v1/openapi.json"
    # served under a versioned docs_url that our static list can't guess).
    for dp in _DOCS_TO_SCRAPE:
        try:
            r = requests.get(f"{base}{dp}", timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200 or "html" not in r.headers.get("content-type", "").lower():
            continue
        seen: set = set()
        for m in _OPENAPI_HREF_RE.finditer(r.text):
            cand = m.group(1)
            if cand.startswith("http"):
                from urllib.parse import urlparse
                cand = urlparse(cand).path
            if not cand.startswith("/"):
                cand = "/" + cand
            if cand in seen:
                continue
            seen.add(cand)
            hit = _try_spec(base, cand, timeout)
            if hit:
                return hit
    return None


def discover_doc_paths(base_url: str, timeout: float = 8.0) -> list[str]:
    """Which human-facing API docs are publicly reachable (misconfig signal)."""
    base = base_url.rstrip("/")
    found = []
    for path in DOC_CANDIDATES + ["/openapi.json"]:
        try:
            r = requests.get(f"{base}{path}", timeout=timeout)
            if r.status_code == 200:
                found.append(path)
        except requests.RequestException:
            continue
    return found


def _resolve_ref(ref: str, components: dict) -> dict:
    # "#/components/schemas/Foo" -> components["schemas"]["Foo"]
    if not ref.startswith("#/"):
        return {}
    node: Any = {"components": components}
    for part in ref[2:].split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _deref(schema: dict | None, components: dict, _depth: int = 0) -> dict | None:
    """Shallow-resolve $ref so modules see field names without chasing refs.

    Bounded depth to avoid pathological recursive schemas.
    """
    if not isinstance(schema, dict) or _depth > 6:
        return schema
    if "$ref" in schema:
        return _deref(_resolve_ref(schema["$ref"], components), components, _depth + 1)
    out = dict(schema)
    if "properties" in out and isinstance(out["properties"], dict):
        out["properties"] = {
            k: _deref(v, components, _depth + 1) for k, v in out["properties"].items()
        }
    for combiner in ("allOf", "anyOf", "oneOf"):
        if combiner in out and isinstance(out[combiner], list):
            out[combiner] = [_deref(s, components, _depth + 1) for s in out[combiner]]
    return out


def parse_routes(spec: dict) -> RouteMap:
    components = spec.get("components", {})
    rm = RouteMap(openapi=spec, components=components)
    paths = spec.get("paths", {})
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters", [])
        for method, op in item.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            if not isinstance(op, dict):
                continue
            params = list(shared_params) + list(op.get("parameters", []))
            path_params = [p["name"] for p in params
                           if isinstance(p, dict) and p.get("in") == "path"]
            query_params = [p for p in params
                            if isinstance(p, dict) and p.get("in") == "query"]
            # security: operation-level overrides global; [] means "explicitly public".
            sec = op.get("security", spec.get("security", []))
            secured = bool(sec) and any(bool(s) for s in sec)

            body_schema = None
            rb = op.get("requestBody", {})
            content = rb.get("content", {}) if isinstance(rb, dict) else {}
            for ct in ("application/json", "application/x-www-form-urlencoded",
                       "multipart/form-data"):
                if ct in content:
                    body_schema = _deref(content[ct].get("schema"), components)
                    break

            resp_fields = _response_field_names(op, components)

            rm.routes.append(Route(
                path=path,
                method=method.upper(),
                operation_id=op.get("operationId", ""),
                summary=op.get("summary", ""),
                tags=list(op.get("tags", [])),
                secured=secured,
                path_params=path_params,
                query_params=query_params,
                body_schema=body_schema,
                response_fields=resp_fields,
                raw=op,
            ))
    return rm


def _response_field_names(op: dict, components: dict) -> list[str]:
    """Property names of the first 2xx JSON response schema (statefulness signal:
    a response carrying balance/stock/scanned/remaining betrays a mutable resource)."""
    responses = op.get("responses", {})
    if not isinstance(responses, dict):
        return []
    for code in ("200", "201", "202"):
        r = responses.get(code)
        if not isinstance(r, dict):
            continue
        schema = (r.get("content", {}).get("application/json", {}) or {}).get("schema")
        schema = _deref(schema, components)
        if isinstance(schema, dict):
            if schema.get("type") == "array":
                schema = _deref(schema.get("items"), components) or {}
            props = schema.get("properties")
            if isinstance(props, dict):
                return list(props.keys())
    return []


def body_field_names(route: Route) -> list[str]:
    """Best-effort list of request-body field names for a route."""
    schema = route.body_schema or {}
    props = schema.get("properties")
    if isinstance(props, dict):
        return list(props.keys())
    for combiner in ("allOf", "anyOf", "oneOf"):
        for sub in schema.get(combiner, []):
            if isinstance(sub, dict) and isinstance(sub.get("properties"), dict):
                return list(sub["properties"].keys())
    return []


def required_body_fields(route: Route) -> list[str]:
    schema = route.body_schema or {}
    req = schema.get("required")
    return list(req) if isinstance(req, list) else []
