"""A05 — GraphQL exposure.

Only applies when the app actually mounts a GraphQL endpoint (Strawberry /
Ariadne / graphene on FastAPI). This module first *finds* one — probing the
conventional paths with a tiny ``{__typename}`` query — and cleanly no-ops on a
pure-REST app (like most FastAPI backends), so it's safe to always run.

If a GraphQL endpoint answers, it checks the two issues that are (a) black-box
detectable and (b) almost always misconfigurations rather than app bugs:

  * **Introspection enabled** — a full ``__schema`` query returns the entire API
    shape (every type, field, mutation, and argument). Great for the attacker's
    map of the attack surface; should be off in production.
  * **Field suggestions** — a misspelled field triggers a "Did you mean …?"
    hint, which leaks schema detail even with introspection disabled.

Deeper GraphQL issues (field-level authz, batching/alias DoS, injection through
resolvers) need the schema and per-app knowledge, so they're out of scope for a
generic black-box pass; we point the report at them.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

_CANDIDATE_PATHS = ("/graphql", "/graphql/", "/api/graphql", "/v1/graphql",
                    "/graphql/v1", "/query", "/gql", "/api/gql",
                    # some apps mount the GraphQL ASGI app at root (Ariadne
                    # `app.mount("/", GraphQL(...))`); tried LAST + confirmed by a
                    # real GraphQL probe response, so a REST "/" won't false-match
                    "/")

_PROBE_QUERY = {"query": "{__typename}"}
_INTROSPECTION = {"query": "query{__schema{queryType{name} types{name}}}"}
_TYPO_QUERY = {"query": "{__typename thisFieldDoesNotExistHeimdall}"}


@module("graphql", "GraphQL Exposure")
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    endpoint = _find_graphql(ctx, token)
    if not endpoint:
        ctx.note("graphql: no GraphQL endpoint found (REST app) — nothing to test")
        return

    ctx.note(f"graphql: endpoint at {endpoint}")
    introspects = _introspection_enabled(ctx, endpoint, token)
    suggests = _suggestions_enabled(ctx, endpoint, token)

    if introspects or suggests:
        _report_issues(ctx, endpoint, introspects, suggests)
    else:
        _report_safe(ctx, endpoint)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery ────────────────────────────────────────────────────────────────

def _paths_to_try(ctx: Context) -> list[str]:
    paths = list(_CANDIDATE_PATHS)
    # Also honour any graphql-ish path already in the route map.
    for r in ctx.routes:
        if "graphql" in r.path.lower() or r.path.lower().endswith("/gql"):
            if r.path not in paths:
                paths.append(r.path)
    return paths


def _is_graphql_response(resp) -> bool:
    ctype = resp.headers.get("Content-Type", "").lower()
    if "json" not in ctype:
        return False
    try:
        data = resp.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("data"), dict) and "__typename" in data["data"]:
        return True
    # GraphQL error envelope for our probe.
    errs = data.get("errors")
    if isinstance(errs, list) and errs:
        blob = str(errs).lower()
        return any(s in blob for s in ("graphql", "cannot query", "syntax",
                                       "must provide query", "__typename"))
    return False


def _find_graphql(ctx: Context, token) -> str | None:
    for path in _paths_to_try(ctx):
        try:
            resp = ctx.post(path, json=_PROBE_QUERY, token=token, timeout=8,
                            retry_429=False)
        except requests.RequestException:
            continue
        if resp.status_code < 500 and _is_graphql_response(resp):
            return path
    return None


# ── checks ───────────────────────────────────────────────────────────────────

def _introspection_enabled(ctx: Context, endpoint: str, token) -> bool:
    try:
        resp = ctx.post(endpoint, json=_INTROSPECTION, token=token, timeout=8,
                        retry_429=False)
        data = resp.json()
    except Exception:
        return False
    return bool(isinstance(data, dict)
                and isinstance(data.get("data"), dict)
                and data["data"].get("__schema"))


def _suggestions_enabled(ctx: Context, endpoint: str, token) -> bool:
    try:
        resp = ctx.post(endpoint, json=_TYPO_QUERY, token=token, timeout=8,
                        retry_429=False)
        blob = str(resp.json()).lower()
    except Exception:
        return False
    return "did you mean" in blob


# ── findings ─────────────────────────────────────────────────────────────────

def _report_issues(ctx, endpoint, introspects, suggests) -> None:
    bits = []
    if introspects:
        bits.append("full schema introspection is enabled")
    if suggests:
        bits.append("field suggestions ('Did you mean …?') are enabled")
    ctx.finding(
        id="a05-graphql-introspection",
        owasp="A05", severity="MEDIUM" if introspects else "LOW",
        title=f"GraphQL {'introspection' if introspects else 'field suggestions'} "
              f"exposed at {endpoint}",
        summary=(
            f"The GraphQL endpoint at {endpoint} leaks its schema: "
            + " and ".join(bits) + ". "
            "This hands an attacker a complete map of every type, field, mutation "
            "and argument — the fastest route to finding an unprotected mutation "
            "or an over-permissive field. Disable introspection and field "
            "suggestions in production, and separately verify per-field "
            "authorization, query depth/complexity limits, and batching/alias "
            "abuse controls (not covered by this black-box check)."
        ),
        evidence=f"POST {endpoint}  {_INTROSPECTION['query']!r}  -> __schema returned"
                 if introspects else
                 f"POST {endpoint}  misspelled field -> 'Did you mean' suggestion",
        route=f"POST {endpoint}",
        request=f"POST {endpoint}  body {_INTROSPECTION if introspects else _TYPO_QUERY}",
        reproduction=(
            f"POST {endpoint} with a GraphQL introspection query "
            "(query{__schema{types{name fields{name}}}}) and read the full schema; "
            "then enumerate mutations for missing authorization."
        ),
        references=[REFS["A05"],
                    "https://portswigger.net/web-security/graphql",
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "GraphQL_Cheat_Sheet.html"],
        tools=["InQL", "graphw00f", "clairvoyance", "Burp Suite"],
    )


def _report_safe(ctx, endpoint) -> None:
    ctx.finding(
        id="a05-graphql-safe",
        owasp="A05", severity="SAFE",
        title=f"GraphQL endpoint at {endpoint} has introspection disabled",
        summary=(
            f"A GraphQL endpoint responds at {endpoint}, but introspection and "
            "field suggestions are both disabled — the schema isn't handed out "
            "black-box. Still verify per-field authorization and query "
            "depth/complexity/batching limits, which this generic check can't "
            "assess without the schema."
        ),
        references=[REFS["A05"], "https://portswigger.net/web-security/graphql"],
    )
