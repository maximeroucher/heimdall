"""A01 / API3 — Mass assignment (broken object property-level authorization).

An endpoint that binds the request body straight onto its model accepts *more*
than the fields it documents as input — so a client can set fields the server was
supposed to own (a role, an approval flag, an owner id, a balance).

Detection is HINT-FREE — no hardcoded "privileged field" name list (the discipline
the race/workflow/business-logic modules follow). The app itself tells us which
fields are server-controlled: they appear in the endpoint's **response** schema
but not in its **request** schema. Those are exactly the properties a client
should not be able to write. So:

  1. Structurally diff response-fields − request-fields → the server-controlled
     properties (derived from the app's OpenAPI, not guessed).
  2. Create the object once to learn each such field's type, then create it again
     injecting a type-matched distinctive value into every server-controlled field.
  3. If the object comes back carrying our injected value, the server bound a
     field it never declared as input — confirmed mass assignment.

This catches whatever the app over-binds (is_admin, owner_id, an app-specific
internal_status …) without naming any of them. Writes objects → FULL mode only.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

_MARK_STR = "heimdall_ma"
_MARK_NUM = 1337421
_MAX_ROUTES = 30


@module("mass-assignment", "Mass Assignment", destructive=True)
def run(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("mass-assignment: skipped (writes objects; FULL mode only)")
        return
    token = _actor_token(ctx)
    routes = _discover(ctx)
    if not routes:
        ctx.note("mass-assignment: no endpoints expose server-only fields to test")
        return

    hits: list[dict] = []
    tested = unreached = 0
    for route, cands in routes[:_MAX_ROUTES]:
        outcome = _probe(ctx, route, cands, token)
        if outcome == "unreached":
            unreached += 1
        elif outcome == "clean":
            tested += 1
        elif isinstance(outcome, dict):
            tested += 1
            hits.append(outcome)

    ctx.note(f"mass-assignment: tested {tested} endpoint(s) for over-binding of "
             f"server-only fields; {len(hits)} bound one, {unreached} unreachable")
    if hits:
        _report(ctx, hits)
    elif tested:
        _report_safe(ctx, tested, unreached)
    elif unreached:
        _report_untested(ctx, unreached)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery (structural schema diff — no names inspected) ──────────────────

def _discover(ctx: Context) -> list[tuple]:
    """Pair each write endpoint with the server-controlled fields it exposes:
    response properties that are NOT request properties."""
    out = []
    for r in ctx.routes:
        if r.method not in ("POST", "PUT", "PATCH"):
            continue
        req = {f.lower() for f in body_field_names(r)}
        cands = [f for f in r.response_fields if f.lower() not in req]
        if req and cands:            # needs a real request body AND server-only fields
            out.append((r, cands))
    return out


# ── probing (behavioural: inject server-only fields, confirm persistence) ────

def _fire(ctx, route, token, overrides):
    path = route.fill_path({p: "1" for p in route.path_params})
    try:
        _, body = build_request(ctx, route, token, overrides=overrides)
        resp = ctx.request(route.method, path, token=token, json=body,
                           timeout=12, retry_429=False)
    except requests.RequestException:
        return None
    return resp


def _obj(resp):
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return None
    if isinstance(data, dict):
        # unwrap a single-object envelope if present
        for k in ("data", "item", "result", "object"):
            if isinstance(data.get(k), dict):
                return data[k]
        return data
    return None


def _distinctive(value):
    """A type-matched value that can only have come from us, or None to skip."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return _MARK_STR
    if isinstance(value, (int, float)):
        return _MARK_NUM
    return None


_MISSING = object()


def _injectable_fields(cands, o0, o0b):
    """Server-only fields worth injecting into: present in the baseline object,
    distinctively type-settable, and DETERMINISTIC across two identical baseline
    creates (``o0b`` — may be None if a second baseline wasn't obtained).

    The determinism gate is what keeps this precise: a field that varies between
    two identical creates (a random A/B bucket, a cache / ``is_new`` flag, a
    timestamp) could coincidentally match our injected value — for a boolean
    that's a 50/50 false positive — so we never test it and can only attribute a
    persisted value to genuine over-binding."""
    inject = {}
    for c in cands:
        if c not in o0:
            continue
        if o0b is not None and o0b.get(c, _MISSING) != o0[c]:
            continue                 # non-deterministic server field — skip
        d = _distinctive(o0[c])
        if d is not None and d != o0[c]:
            inject[c] = d
    return inject


def _probe(ctx, route, cands, token):
    # Phase 1: baseline create TWICE — learn the server-controlled fields' types
    # and confirm each is deterministic (a field that differs between two
    # identical creates can't be attributed to our injection, see below).
    r0 = _fire(ctx, route, token, {})
    if r0 is None or r0.status_code >= 400:
        return "unreached"
    o0 = _obj(r0)
    if not o0:
        return "unreached"
    r0b = _fire(ctx, route, token, {})
    o0b = _obj(r0b) if (r0b is not None and r0b.status_code < 400) else None

    inject = _injectable_fields(cands, o0, o0b)
    if not inject:
        return "clean"               # server-only fields absent/untypable/unstable

    # Phase 2: create again, injecting a distinctive value into every such field.
    r1 = _fire(ctx, route, token, inject)
    if r1 is None or r1.status_code >= 400:
        return "clean"               # rejected the injected fields → not bound
    o1 = _obj(r1)
    if not o1:
        return "clean"
    bound = [(c, o0.get(c), o1[c]) for c, v in inject.items()
             if c in o1 and o1[c] == v and o1[c] != o0.get(c)]
    if bound:
        return {"route": route, "bound": bound}
    return "clean"


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx: Context, hits: list[dict]) -> None:
    lead = hits[0]
    r = lead["route"]
    lines = []
    for h in hits[:15]:
        hr = h["route"]
        fields = ", ".join(f"{c} ({old}→{new})" for c, old, new in h["bound"][:5])
        lines.append(f"  {hr.method} {hr.path}  bound server-only field(s): {fields}")
    all_fields = sorted({c for h in hits for c, _o, _n in h["bound"]})
    lead_fields = ", ".join(c for c, _o, _n in lead["bound"][:3])
    ctx.finding(
        id="a01-mass-assignment",
        owasp="A01", severity="HIGH",
        title=(f"Mass assignment on {r.method} {r.path} — client-writable "
               f"server field(s): {lead_fields}"
               + (f" (+{len(hits) - 1} more endpoint(s))" if len(hits) > 1 else "")),
        summary=(
            "The endpoint bound request-body fields it never declares as input: "
            "properties that appear only in its response schema (server-controlled "
            "— set by the server, not the client) were writable, and our injected "
            "values persisted. These are the fields the API author chose to expose "
            "as output-only, so being able to set them is a property-level "
            "authorization break. Its severity depends on which field — writing an "
            "authorization flag (is_admin/role/verified), an ownership id, or a "
            "balance is privilege escalation / takeover / financial tampering; the "
            f"over-bound fields here are: {', '.join(all_fields)}. Fix: bind an "
            "explicit per-endpoint input schema (a dedicated Pydantic model with "
            "only the client-writable fields — never the ORM model or a shared "
            "schema) and set server-owned fields server-side only."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=f"{r.method} {r.path}  (body + server-only field {lead['bound'][0][0]})",
        reproduction=(
            f"Create via {r.method} {r.path} once to see the server-set fields in "
            f"the response, then create again with '{lead['bound'][0][0]}' set in "
            f"the body; the response comes back carrying your value "
            f"({lead['bound'][0][1]} → {lead['bound'][0][2]}), proving the server "
            "bound a field it doesn't declare as input."
        ),
        references=[REFS["A01"], REFS["api3"], REFS["ps-massassign"],
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Mass_Assignment_Cheat_Sheet.html"],
        tools=["Burp Suite (Repeater)", "curl"],
    )


def _report_safe(ctx: Context, tested: int, unreached: int) -> None:
    ctx.finding(
        id="a01-mass-assignment-safe",
        owasp="A01", severity="SAFE",
        title="Server-controlled fields are not client-writable",
        summary=(
            f"For {tested} write endpoint(s), injected distinctive values into "
            "every field the response exposes but the request schema does not "
            "(the server-controlled properties); none persisted, consistent with "
            "explicit input schemas that drop undeclared fields. "
            + (f"{unreached} endpoint(s) couldn't be exercised. " if unreached else "")
            + "Endpoints whose response doesn't echo the object can't be confirmed "
            "this way — re-fetch those manually."
        ),
        references=[REFS["A01"], REFS["api3"], REFS["ps-massassign"]],
    )


def _report_untested(ctx: Context, unreached: int) -> None:
    ctx.finding(
        id="a01-mass-assignment-untested",
        owasp="A01", severity="INFO",
        title=f"{unreached} endpoint(s) with server-only fields not exercised",
        summary=(
            f"Found {unreached} write endpoint(s) exposing server-controlled fields, "
            "but the baseline create/update didn't succeed (preconditions / related "
            "resources / authorization black-box synthesis couldn't satisfy), so "
            "over-binding wasn't tested — not a clean bill of health. Re-run with "
            "valid prerequisites or test these manually."
        ),
        references=[REFS["A01"], REFS["api3"]],
    )
