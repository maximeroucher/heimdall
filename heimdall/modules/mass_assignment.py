"""A01 / API3 — Mass assignment (broken object property-level authorization).

An endpoint that binds the request body straight onto a model accepts *more*
than the fields it documents: send ``is_admin: true`` or ``role: "admin"`` to a
profile-update or signup endpoint and, if the server binds it, you've granted
yourself privileges the API never meant to expose. This is the write side of
property-level authorization (OWASP API3) — and it's broader than the two spots
already covered (a07 signup, a01 self-escalation on ``/me``): it applies to
*every* create/update endpoint.

Detection is confirmation-based, not guesswork: inject privileged fields the
endpoint does **not** declare, using distinctive marker values that could only
come from us (``role: "heimdall_root"``, ``balance: 1337421``), then check
whether the response reflects that marker back — proof the server accepted and
stored the unexpected field. Only extra (undeclared) fields are injected, and it
writes objects, so it's FULL-mode only.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

# Privileged fields with distinctive marker values. Booleans use True; the
# string/number markers are unguessable so a reflection is unambiguous proof.
_MARK_S = "heimdall_root"
_MARK_OWN = "heimdall-owns-9e3f"
_MARK_STATUS = "heimdall_pwned"
_MARK_N = 1337421

_PRIV_FIELDS: dict = {
    "is_admin": True, "is_superuser": True, "is_staff": True, "admin": True,
    "superuser": True, "is_active": True, "is_verified": True, "verified": True,
    "email_verified": True, "is_approved": True, "approved": True,
    "is_premium": True, "is_confirmed": True, "is_owner": True,
    "role": _MARK_S, "account_type": _MARK_S, "user_role": _MARK_S,
    "permissions": [_MARK_S], "scopes": [_MARK_S],
    "balance": _MARK_N, "credit": _MARK_N, "wallet_balance": _MARK_N,
    "owner_id": _MARK_OWN, "user_id": _MARK_OWN, "created_by": _MARK_OWN,
    "status": _MARK_STATUS,
}
# Which persisted fields are privilege/financial (HIGH) vs ownership (MEDIUM).
_HIGH_KEYS = {"is_admin", "is_superuser", "is_staff", "admin", "superuser",
              "role", "account_type", "user_role", "permissions", "scopes",
              "is_verified", "verified", "email_verified", "is_approved",
              "approved", "is_active", "balance", "credit", "wallet_balance"}
_MARKERS = {_MARK_S, _MARK_OWN, _MARK_STATUS, _MARK_N}
_MAX_ROUTES = 25


@module("mass-assignment", "Mass Assignment", destructive=True)
def run(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("mass-assignment: skipped (writes objects; FULL mode only)")
        return
    token = _actor_token(ctx)
    routes = [r for r in ctx.routes if r.method in ("POST", "PUT", "PATCH")
              and (r.body_schema or {}).get("properties")][:_MAX_ROUTES]
    if not routes:
        ctx.note("mass-assignment: no writable endpoints with a body schema")
        return

    hits: list[dict] = []
    probed = 0
    for r in routes:
        probed += 1
        _probe(ctx, r, token, hits)

    ctx.note(f"mass-assignment: probed {probed} write endpoint(s); "
             f"{len(hits)} bound an undeclared privileged field")
    if hits:
        _report(ctx, hits)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


def _probe(ctx, route, token, hits: list[dict]) -> None:
    declared = set(body_field_names(route))
    # Only inject fields the endpoint does NOT already declare — that's what
    # makes it *mass* assignment rather than intended input.
    inject = {k: v for k, v in _PRIV_FIELDS.items() if k not in declared}
    if not inject:
        return
    path = route.fill_path({p: "1" for p in route.path_params})
    data = _send(ctx, route, path, token, inject)
    if data is None:
        return

    injected_bools = {k for k, v in inject.items() if v is True}
    # Distinctive string/number markers echoed back are unambiguous proof.
    markers = _marker_hits(data)
    # Boolean flags are ambiguous (the value may just be the model default), so
    # CONFIRM control with a differential: resend the same booleans as False and
    # require the response to track our input (True→true earlier, now False→false).
    bool_hits = []
    bool_candidates = _bool_true_hits(data, injected_bools)
    if bool_candidates:
        inject_false = {k: (False if k in injected_bools else v)
                        for k, v in inject.items()}
        data2 = _send(ctx, route, path, token, inject_false)
        if data2 is not None:
            vals2 = {kp: v for kp, _k, v in _walk(data2)}
            bool_hits = [(kp, True) for kp in bool_candidates
                         if vals2.get(kp) is False]  # value followed our input

    bound = _dedup(markers + bool_hits)
    if bound:
        hits.append({"route": route, "bound": bound})


def _send(ctx, route, path, token, inject):
    try:
        _, body = build_request(ctx, route, token, overrides=inject)
        resp = ctx.request(route.method, path, token=token, json=body,
                           timeout=12, retry_429=False)
    except requests.RequestException:
        return None
    if resp.status_code >= 400:
        return None
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return None


def _marker_hits(data) -> list[tuple]:
    out = []
    for keypath, _key, value in _walk(data):
        if value in _MARKERS or (isinstance(value, list) and _MARK_S in value):
            out.append((keypath, value))
    return out


def _bool_true_hits(data, injected_bools: set) -> list[str]:
    return [kp for kp, key, value in _walk(data)
            if key in injected_bools and value is True]


def _dedup(pairs: list[tuple]) -> list[tuple]:
    seen, out = set(), []
    for kp, v in pairs:
        if kp not in seen:
            seen.add(kp)
            out.append((kp, v))
    return out


def _walk(obj, prefix="", depth=0):
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk(v, kp, depth + 1)
            else:
                yield kp, str(k), v
    elif isinstance(obj, list):
        for item in obj[:20]:
            yield from _walk(item, prefix + "[]", depth + 1)


# ── findings ─────────────────────────────────────────────────────────────────

def _is_high(bound: list[tuple]) -> bool:
    return any(kp.split(".")[-1] in _HIGH_KEYS for kp, _v in bound)


def _report(ctx: Context, hits: list[dict]) -> None:
    high = any(_is_high(h["bound"]) for h in hits)
    lead = next((h for h in hits if _is_high(h["bound"])), hits[0])
    r = lead["route"]
    lines = []
    for h in hits[:15]:
        hr = h["route"]
        fields = ", ".join(f"{kp}={v}" for kp, v in h["bound"][:5])
        lines.append(f"  {hr.method} {hr.path}  bound → {fields}")
    ctx.finding(
        id="a01-mass-assignment",
        owasp="A01", severity="HIGH" if high else "MEDIUM",
        title=(f"Mass assignment on {r.method} {r.path} "
               f"(bound undeclared {lead['bound'][0][0].split('.')[-1]})"
               + (f" (+{len(hits) - 1} more)" if len(hits) > 1 else "")),
        summary=(
            "The endpoint bound request-body fields it never declares onto its "
            "model: privileged properties injected with unguessable marker values "
            "came back in the response, proving the server accepted and stored "
            "them. "
            + ("A client can set is_admin / role / verified / balance on itself — "
               "privilege escalation, moderation bypass, or financial tampering "
               "in a single request. "
               if high else
               "A client can reassign ownership fields (owner_id/user_id) it "
               "shouldn't control. ")
            + "Bind an explicit allow-list of writable fields (a dedicated "
            "Pydantic input schema per endpoint — never the ORM model / a shared "
            "schema), and set server-controlled fields server-side only."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=f"{r.method} {r.path}  (body + undeclared {lead['bound'][0][0].split('.')[-1]})",
        reproduction=(
            f"Send {r.method} {r.path} with the normal body plus "
            f"'{lead['bound'][0][0].split('.')[-1]}' set to a privileged value; "
            f"the response reflects it, confirming the server bound the "
            f"undeclared field."
        ),
        references=[REFS["A01"], REFS["api3"], REFS["ps-massassign"],
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Mass_Assignment_Cheat_Sheet.html"],
        tools=["Burp Suite (Repeater)", "curl"],
    )


def _report_safe(ctx: Context, probed: int) -> None:
    ctx.finding(
        id="a01-mass-assignment-safe",
        owasp="A01", severity="SAFE",
        title="Write endpoints ignore undeclared privileged fields",
        summary=(
            f"Injected undeclared privileged fields (is_admin, role, verified, "
            f"balance, owner_id, …) with marker values into {probed} write "
            "endpoint(s); none were reflected back, consistent with explicit "
            "input schemas that drop unexpected fields. Endpoints whose response "
            "doesn't echo the object can't be confirmed this way — re-fetch those "
            "objects manually to be sure."
        ),
        references=[REFS["A01"], REFS["api3"], REFS["ps-massassign"]],
    )
