"""A04 / API6 — Multi-step logic: replayable double-effect (behavioural).

Single-request probes miss logic flaws that need a *sequence*. The one this
finds: an action that should apply once per resource but has no state check, so
firing it again re-applies it — a double-redeem / double-spend / double-vote.

This is deliberately HINT-FREE — no verb lists, no field-name lists (the same
discipline as the race module). It never decides "this looks like a redeem".
Instead it works purely from observed behaviour:

  * Discovery is structural: a mutating endpoint (POST/PUT/PATCH/DELETE) that
    targets a specific resource (a path param) AND has a readable GET for that
    same resource. No names are inspected.
  * The oracle is state movement: read the target resource, fire the action, read
    it, fire the identical action again, read it. If some numeric field advances
    on BOTH fires in the same direction, the action re-applies every time it's
    replayed — a cumulative double-effect. If the second fire is instead rejected,
    the resource enforces single-use (good). If nothing moves, it's idempotent.

Distinct from `race`: race defeats a once-guard with a *concurrency window*; this
is *sequential* — the state machine never checks the resource's state at all, so
it double-applies with no race. Consumes state, so FULL mode only.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request, harvest_id
from ..core.taxonomy import REFS
from .base import module

_MAX_ACTIONS = 30


@module("workflow", "Multi-step Logic (Replay Double-Effect)", destructive=True)
def run(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("workflow: skipped (consumes state; FULL mode only)")
        return
    token = _actor_token(ctx)
    pairs = _discover(ctx)
    if not pairs:
        ctx.note("workflow: no resource-targeting mutations with a readable GET")
        return

    confirmed: list[dict] = []
    enforced = idempotent = unreached = 0
    probed = 0
    for action, state in pairs[:_MAX_ACTIONS]:
        probed += 1
        outcome = _probe(ctx, action, state, token)
        if outcome == "enforced":
            enforced += 1
        elif outcome == "idempotent":
            idempotent += 1
        elif outcome == "unreached":
            unreached += 1
        elif isinstance(outcome, dict):
            confirmed.append(outcome)

    ctx.note(f"workflow: replayed {probed} resource mutation(s) twice — "
             f"{len(confirmed)} re-applied cumulatively, {enforced} rejected the "
             f"replay, {idempotent} idempotent, {unreached} unreachable")
    if confirmed:
        _report(ctx, confirmed)
    elif enforced or idempotent:
        _report_safe(ctx, enforced, idempotent, unreached)
    elif unreached:
        _report_untested(ctx, unreached)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery (structural only — no names inspected) ─────────────────────────

def _discover(ctx: Context) -> list[tuple]:
    """Pair each resource-targeting mutation with the GET that reads that same
    resource. Matching is purely by path structure: the state GET's path is the
    mutation's path or a prefix of it, and both carry the resource's path param."""
    gets = [r for r in ctx.routes if r.method == "GET" and r.has_path_param]
    pairs, seen = [], set()
    for r in ctx.routes:
        if r.method not in ("POST", "PUT", "PATCH", "DELETE") or not r.has_path_param:
            continue
        best = None
        for g in gets:
            if not (r.path == g.path or r.path.startswith(g.path.rstrip("/") + "/")):
                continue
            # the GET must resolve the same resource — share its path params
            if not set(g.path_params) <= set(r.path_params):
                continue
            if best is None or len(g.path) > len(best.path):
                best = g
        if best is not None and r.key not in seen:
            seen.add(r.key)
            pairs.append((r, best))
    return pairs


# ── probing (behavioural oracle) ─────────────────────────────────────────────

def _num_map(ctx, path, token) -> dict:
    """Every numeric leaf in the resource's current representation."""
    try:
        r = ctx.get(path, token=token, timeout=8, retry_429=False)
        if r.status_code >= 400:
            return {}
        data = r.json()
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


def _fire(ctx, route, path, body, token):
    kw = {"token": token, "timeout": 12, "retry_429": False}
    if route.method != "DELETE" and body:
        kw["json"] = body
    try:
        return ctx.request(route.method, path, **kw)
    except requests.RequestException:
        return None


def _probe(ctx, action, state, token):
    # Resolve the target resource id ONCE so the action and its state GET refer to
    # the same object; fill both paths with it.
    vals = {p: (harvest_id(ctx, p, token, action.path) or "1")
            for p in action.path_params}
    a_path = action.fill_path(vals)
    s_path = state.fill_path({p: vals.get(p, "1") for p in state.path_params})
    _, body = build_request(ctx, action, token)   # body only; path resolved above

    s0 = _num_map(ctx, s_path, token)
    r1 = _fire(ctx, action, a_path, body, token)
    if r1 is None or r1.status_code >= 400:
        return "unreached"
    s1 = _num_map(ctx, s_path, token)
    r2 = _fire(ctx, action, a_path, body, token)
    if r2 is None:
        return "unreached"
    if r2.status_code >= 400:
        return "enforced"              # replay rejected → single-use enforced ✓
    s2 = _num_map(ctx, s_path, token)

    # Cumulative: a field moved on BOTH fires, in the same direction.
    moved = []
    for kp in s0:
        if kp in s1 and kp in s2:
            d1, d2 = s1[kp] - s0[kp], s2[kp] - s1[kp]
            if d1 != 0 and d2 != 0 and (d1 > 0) == (d2 > 0):
                moved.append((kp, s0[kp], s1[kp], s2[kp]))
    if moved:
        return {"action": action, "state": state, "moved": moved}
    return "idempotent"


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx: Context, confirmed: list[dict]) -> None:
    lead = confirmed[0]
    r = lead["action"]
    lines = []
    for c in confirmed[:15]:
        cr = c["action"]
        kp, v0, v1, v2 = c["moved"][0]
        lines.append(f"  {cr.method} {cr.path}  replayed → {kp} moved "
                     f"{v0}→{v1}→{v2} (advanced on each identical fire)")
    ctx.finding(
        id="a04-replay-double-effect",
        owasp="A04", severity="HIGH",
        title=(f"Replayable state mutation on {r.method} {r.path} "
               "(cumulative double-effect)"
               + (f" (+{len(confirmed) - 1} more)" if len(confirmed) > 1 else "")),
        summary=(
            "Firing this mutation twice in a row re-applied it both times: a "
            "numeric field on the target resource advanced on each identical "
            "request, so the endpoint enforces no state check on the resource's "
            "current value. If that field is a consumable (a balance, a stock "
            "count, a vote tally, a remaining-uses counter) this is a "
            "double-spend / double-redeem / double-vote — an attacker repeats the "
            "request to keep applying the effect. (Verify the moved field is a "
            "consumable and not a benign version/revision counter.) Enforce the "
            "transition atomically — a single conditional/locked UPDATE that only "
            "succeeds from the expected prior state — so any replay (sequential or "
            "concurrent) is rejected. This is the sequential complement to the "
            "race/TOCTOU check."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=f"{r.method} {r.path}  (fired twice, sequentially)",
        reproduction=(
            f"Read the target resource, {r.method} {r.path}, read it again, "
            f"{r.method} {r.path} once more: the field "
            f"{lead['moved'][0][0]} advances on each fire "
            f"({lead['moved'][0][1]}→{lead['moved'][0][2]}→{lead['moved'][0][3]}), "
            "confirming the action re-applies without a state check."
        ),
        references=[REFS["A04"], REFS["api6"],
                    "https://portswigger.net/web-security/logic-flaws"],
        tools=["Burp Suite (Repeater)", "curl"],
    )


def _report_safe(ctx: Context, enforced: int, idempotent: int, unreached: int) -> None:
    ctx.finding(
        id="a04-workflow-safe",
        owasp="A04", severity="SAFE",
        title="Replayed mutations enforce single-use or are idempotent",
        summary=(
            f"Replayed resource mutations twice each and watched the target's "
            f"state: {enforced} rejected the second, sequential fire (single-use "
            f"enforced) and {idempotent} left the resource unchanged on the repeat "
            "(idempotent) — neither double-applies. "
            + (f"{unreached} could not be exercised (preconditions unmet) and "
               "weren't tested. " if unreached else "")
            + "This covers sequential replay; the race module covers the "
            "concurrent (TOCTOU) variant. App-specific multi-step flows (coupon "
            "stacking via add/remove, checkout step-skipping) still need manual "
            "modelling."
        ),
        references=[REFS["A04"], REFS["api6"]],
    )


def _report_untested(ctx: Context, unreached: int) -> None:
    ctx.finding(
        id="a04-workflow-untested",
        owasp="A04", severity="INFO",
        title=f"{unreached} resource mutation(s) could not be replay-tested",
        summary=(
            f"Found {unreached} resource-targeting mutation(s) with a readable GET, "
            "but the first fire didn't succeed (they need specific preconditions / "
            "resource state / authorization that black-box synthesis couldn't "
            "satisfy), so replay behaviour was not exercised — this is NOT a clean "
            "bill of health. Re-run with a valid seeded resource in the required "
            "state, or test these flows manually for double-execution."
        ),
        references=[REFS["A04"], REFS["api6"]],
    )
