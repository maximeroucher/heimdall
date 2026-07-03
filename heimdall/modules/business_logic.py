"""A04 / API6 — Business-logic numeric abuse.

The highest-impact API bugs are often not injection but *logic*: a money or
quantity field that accepts a value it never should. A negative ``amount`` that
credits instead of debits a wallet, a negative ``quantity`` that underpays an
order, an oversized value that overflows a total — these pass every syntactic
validator and only a business rule would catch them.

Black-box we can't prove the downstream effect, but we can find the *missing
validation* that enables it: take a money/quantity field, send a benign positive
value (baseline), then send negative / zero / huge values and see whether the
endpoint still accepts them. Acceptance of a negative amount on a
payment/order/wallet field is a strong lead — reported as MEDIUM "verify business
impact", not a confirmed exploit. To keep precision high we only probe fields
whose *name* denotes money or quantity (generic numbers like coordinates or
deltas legitimately go negative), and only when the positive baseline succeeded.

Writes state, so FULL mode only.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

# Field names where a negative / oversized value implies a business-logic abuse.
_MONEY_QTY = ("amount", "price", "quantity", "qty", "count", "total", "balance",
              "credit", "debit", "cost", "sum", "units", "stock", "points",
              "discount", "fee", "cents", "wallet", "refund", "payment",
              "charge", "deposit", "withdraw", "shares", "tokens", "coins")
# Values that a correct money/quantity validator should reject.
_ABUSE_VALUES = [
    ("negative", -100),
    ("zero", 0),
    ("overflow", 2_147_483_648),        # > int32
    ("huge", 10 ** 12),
]
_MAX_FIELDS = 25


@module("business-logic", "Business-Logic Numeric Abuse", destructive=True)
def run(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("business-logic: skipped (writes state; FULL mode only)")
        return
    token = _actor_token(ctx)
    targets = _discover(ctx)
    if not targets:
        ctx.note("business-logic: no money/quantity fields on writable endpoints")
        return

    leads: list[dict] = []
    probed = 0
    for route, field in targets[:_MAX_FIELDS]:
        probed += 1
        _probe_field(ctx, route, field, token, leads)

    ctx.note(f"business-logic: probed {probed} money/quantity field(s); "
             f"{len(leads)} accepted an abusive value")
    if leads:
        _report(ctx, leads)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


def _is_money_qty(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _MONEY_QTY)


def _discover(ctx: Context) -> list[tuple]:
    out, seen = [], set()
    for r in ctx.routes:
        if r.method not in ("POST", "PUT", "PATCH"):
            continue
        props = (r.body_schema or {}).get("properties", {}) or {}
        for name in body_field_names(r):
            sch = props.get(name, {})
            is_num = isinstance(sch, dict) and sch.get("type") in ("integer", "number")
            # fall back to name if schema type is absent/unresolved
            if (is_num or not sch) and _is_money_qty(name) and (r.key, name) not in seen:
                seen.add((r.key, name))
                out.append((r, name))
    return out


def _probe_field(ctx, route, field, token, leads) -> None:
    path = route.fill_path({p: "1" for p in route.path_params})
    # Baseline with a valid positive value; if that path doesn't even work, we
    # can't attribute an abusive acceptance to missing validation.
    try:
        _, base_body = build_request(ctx, route, token, overrides={field: 1})
        base = ctx.request(route.method, path, token=token, json=base_body,
                           timeout=12, retry_429=False)
    except requests.RequestException:
        return
    if base.status_code >= 400:
        return

    accepted = []
    for label, value in _ABUSE_VALUES:
        try:
            _, body = build_request(ctx, route, token, overrides={field: value})
            resp = ctx.request(route.method, path, token=token, json=body,
                               timeout=12, retry_429=False)
        except requests.RequestException:
            continue
        # Only the truly-abusive ones matter: negative/overflow accepted where a
        # money/quantity validator should have rejected them. (Zero is a weaker
        # signal; keep it but don't lead on it.)
        if resp.status_code < 400 and label in ("negative", "overflow", "huge"):
            accepted.append((label, value, resp.status_code))
    if accepted:
        leads.append({"route": route, "field": field, "accepted": accepted,
                      "base_status": base.status_code})


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx: Context, leads: list[dict]) -> None:
    lead = leads[0]
    r = lead["route"]
    lines = []
    for x in leads[:15]:
        xr = x["route"]
        vals = ", ".join(f"{lbl}={val}→HTTP{st}" for lbl, val, st in x["accepted"])
        lines.append(f"  {xr.method} {xr.path}  field '{x['field']}': {vals}")
    ctx.finding(
        id="a04-numeric-business-logic",
        owasp="A04", severity="MEDIUM",
        title=(f"Money/quantity field '{lead['field']}' accepts abusive values on "
               f"{r.method} {r.path}"
               + (f" (+{len(leads) - 1} more)" if len(leads) > 1 else "")),
        summary=(
            "A money/quantity field accepts negative and/or oversized values that "
            "a business-rule validator should reject (the positive-value baseline "
            "was accepted too, so the path is live). Depending on how the value is "
            "used downstream this enables classic logic abuse — a negative amount "
            "that credits a wallet instead of charging it, a negative quantity "
            "that underpays an order, or an overflowed total. This is a LEAD: the "
            "missing input validation is confirmed, the financial impact is not — "
            "trace the field to its effect. Enforce server-side bounds (> 0, "
            "sane maximums) on every money/quantity field."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=f"{r.method} {r.path}  ({lead['field']} = -100 / 2147483648)",
        reproduction=(
            f"Send {r.method} {r.path} with '{lead['field']}': -100 (and again with "
            f"2147483648); both are accepted. Follow the value to its wallet/order/"
            f"total effect to confirm the business impact."
        ),
        references=[REFS["A04"], REFS["api6"],
                    "https://portswigger.net/web-security/logic-flaws"],
        tools=["Burp Suite (Repeater)", "curl"],
    )


def _report_safe(ctx: Context, probed: int) -> None:
    ctx.finding(
        id="a04-numeric-business-logic-safe",
        owasp="A04", severity="SAFE",
        title="Money/quantity fields reject abusive values",
        summary=(
            f"Sent negative, zero and overflow values to {probed} money/quantity "
            "field(s); each was rejected (while a positive baseline was accepted), "
            "consistent with server-side bounds validation. Multi-step logic flows "
            "(coupon reuse, race-based double-spend, workflow-order bypass) aren't "
            "covered by this single-request check and still warrant manual review."
        ),
        references=[REFS["A04"], REFS["api6"]],
    )
