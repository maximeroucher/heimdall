"""A04 / API6 — Business-logic numeric abuse (behavioural, hint-free).

The classic logic bug: a numeric field used in arithmetic with no bound check, so
a negative value inverts the intended effect — a negative "amount" that *credits*
a wallet instead of debiting it, a negative "quantity" that pays you.

This inspects NO field names (no money/quantity keyword list — the same
discipline as the race/workflow modules). It fuzzes *every* numeric body field
and lets behaviour decide, via a sign differential:

  * send the field a positive value, a negative value, and a small baseline;
  * watch every numeric field in the response. If some value moves one way for
    the positive input and the OPPOSITE way for the negative input, the field is
    used in unchecked arithmetic and negation reverses the effect — a confirmed
    exploitable inversion, not a guess. (A value that just echoes the input, or
    an id/timestamp that only ever increases, is excluded automatically.)

If the negative value is instead rejected, the endpoint validates bounds (good).
Writes state, so FULL mode only.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request
from ..core.taxonomy import REFS
from .base import module

_BASE = 1
_POS = 1000
_NEG = -1000
_MAX_FIELDS = 30


@module("business-logic", "Business-Logic Numeric Abuse", destructive=True)
def run(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("business-logic: skipped (writes state; FULL mode only)")
        return
    token = _actor_token(ctx)
    targets = _discover(ctx)
    if not targets:
        ctx.note("business-logic: no numeric body fields on writable endpoints")
        return

    inversions: list[dict] = []
    validated = unreached = 0
    probed = 0
    for route, field in targets[:_MAX_FIELDS]:
        probed += 1
        outcome = _probe_field(ctx, route, field, token)
        if outcome == "validated":
            validated += 1
        elif outcome == "unreached":
            unreached += 1
        elif isinstance(outcome, dict):
            inversions.append(outcome)

    ctx.note(f"business-logic: fuzzed {probed} numeric field(s) with ±values — "
             f"{len(inversions)} inverted under negation, {validated} rejected "
             f"the negative, {unreached} unreachable")
    if inversions:
        _report(ctx, inversions)
    elif validated:
        _report_safe(ctx, validated, unreached)
    elif unreached:
        _report_untested(ctx, unreached)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


def _discover(ctx: Context) -> list[tuple]:
    """Every integer/number body field — by schema type, never by name."""
    out, seen = [], set()
    for r in ctx.routes:
        if r.method not in ("POST", "PUT", "PATCH"):
            continue
        for name, sch in ((r.body_schema or {}).get("properties", {}) or {}).items():
            if isinstance(sch, dict) and sch.get("type") in ("integer", "number") \
                    and (r.key, name) not in seen:
                seen.add((r.key, name))
                out.append((r, name))
    return out


def _fire(ctx, route, field, value, token):
    path = route.fill_path({p: "1" for p in route.path_params})
    try:
        _, body = build_request(ctx, route, token, overrides={field: value})
        resp = ctx.request(route.method, path, token=token, json=body,
                           timeout=12, retry_429=False)
    except requests.RequestException:
        return None
    return resp


def _nums(resp) -> dict:
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    for kp, _key, val in _walk(data):
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            out[kp] = val
    return out


def _walk(obj, prefix="", depth=0):
    if depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk(v, kp, depth + 1)
            else:
                yield kp, str(k), v
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:20]):
            yield from _walk(item, f"{prefix}[{i}]", depth + 1)


def _probe_field(ctx, route, field, token):
    base = _fire(ctx, route, field, _BASE, token)
    if base is None or base.status_code >= 400:
        return "unreached"
    pos = _fire(ctx, route, field, _POS, token)
    neg = _fire(ctx, route, field, _NEG, token)
    if pos is None or neg is None:
        return "unreached"
    if pos.status_code < 400 and neg.status_code >= 400:
        return "validated"          # positive ok, negative rejected → bounds checked ✓
    if pos.status_code >= 400 or neg.status_code >= 400:
        return "unreached"          # positive itself failed — no clean signal

    r0, rp, rn = _nums(base), _nums(pos), _nums(neg)
    inverted = []
    for kp in r0:
        if kp not in rp or kp not in rn:
            continue
        # Skip a value that just echoes our injected input.
        if rp[kp] == _POS and rn[kp] == _NEG:
            continue
        dp, dn = rp[kp] - r0[kp], rn[kp] - r0[kp]
        if dp != 0 and dn != 0 and (dp > 0) != (dn > 0):
            inverted.append((kp, r0[kp], rp[kp], rn[kp]))
    if inverted:
        return {"route": route, "field": field, "inverted": inverted}
    return "validated"              # both accepted but nothing inverted → benign


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx: Context, inversions: list[dict]) -> None:
    lead = inversions[0]
    r = lead["route"]
    lines = []
    for x in inversions[:15]:
        xr = x["route"]
        kp, v0, vp, vn = x["inverted"][0]
        lines.append(f"  {xr.method} {xr.path}  field '{x['field']}': "
                     f"{kp} = {vp} (input +{_POS}) vs {vn} (input {_NEG}) "
                     f"[baseline {v0}] — effect inverts under negation")
    ctx.finding(
        id="a04-numeric-inversion",
        owasp="A04", severity="HIGH",
        title=(f"Sign-inverting numeric field '{lead['field']}' on {r.method} "
               f"{r.path}"
               + (f" (+{len(inversions) - 1} more)" if len(inversions) > 1 else "")),
        summary=(
            "A numeric field is used in unchecked arithmetic: sending it a "
            "positive value moved a result one way and sending it a negative "
            "value moved the same result the OPPOSITE way. Negating the input "
            "reverses the operation's effect — the hallmark of a business-logic "
            "abuse where a negative amount credits instead of charges, a negative "
            "quantity pays the buyer, or a negative transfer drains the other "
            "account. The inversion is observed, not inferred from the field's "
            "name. Enforce server-side bounds (> 0, sane maximums) on every value "
            "that feeds a balance / total / quantity computation."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=f"{r.method} {r.path}  ({lead['field']} = {_NEG})",
        reproduction=(
            f"Send {r.method} {r.path} with '{lead['field']}' = {_POS} and note "
            f"{lead['inverted'][0][0]}={lead['inverted'][0][2]}; resend with "
            f"{lead['field']} = {_NEG} and observe it become "
            f"{lead['inverted'][0][3]} — the effect reverses, so a negative input "
            "runs the operation backwards in the attacker's favour."
        ),
        references=[REFS["A04"], REFS["api6"],
                    "https://portswigger.net/web-security/logic-flaws"],
        tools=["Burp Suite (Repeater)", "curl"],
    )


def _report_safe(ctx: Context, validated: int, unreached: int) -> None:
    ctx.finding(
        id="a04-business-logic-safe",
        owasp="A04", severity="SAFE",
        title="Numeric fields reject or bound negative/oversized values",
        summary=(
            f"Fuzzed numeric body fields with positive and negative values; "
            f"{validated} either rejected the negative outright or produced no "
            "sign-inverting effect (the operation didn't run backwards). "
            + (f"{unreached} could not be exercised (preconditions unmet). "
               if unreached else "")
            + "This catches single-request numeric inversion; multi-step logic "
            "(coupon stacking, workflow step-skipping, quantity limits across "
            "requests) still needs manual modelling."
        ),
        references=[REFS["A04"], REFS["api6"]],
    )


def _report_untested(ctx: Context, unreached: int) -> None:
    ctx.finding(
        id="a04-business-logic-untested",
        owasp="A04", severity="INFO",
        title=f"{unreached} numeric field(s) could not be fuzzed",
        summary=(
            f"Found {unreached} numeric body field(s) but the requests didn't "
            "succeed with a baseline value (preconditions / related resources / "
            "authorization that black-box synthesis couldn't satisfy), so the "
            "±value differential wasn't exercised — not a clean bill of health. "
            "Re-run with valid seeded prerequisites, or test these fields manually."
        ),
        references=[REFS["A04"], REFS["api6"]],
    )
