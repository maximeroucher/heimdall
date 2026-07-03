"""A04 / API4 — Unrestricted resource consumption.

An API that lets the client choose how much work the server does — an unbounded
page size, a bulk endpoint with no item cap — is a denial-of-service and
cost-amplification lever. The correct behaviour is a server-side maximum
(FastAPI `Query(le=100)`, a `maxItems` on the array body); the absence of one is
what we detect:

  1. Pagination cap (active, read-only): send an absurd page-size value
     (``limit=1000000``). A capped endpoint rejects it (422) or clamps it; one
     that answers 2xx enforces no maximum — on a populated table that's a
     table-scan-to-the-client DoS.
  2. Bulk cap (static, no traffic): a request body that is an array with no
     ``maxItems`` constraint accepts arbitrarily large batches.

Both are reported as leads (LOW/MEDIUM) — the missing bound is real; whether it's
weaponizable depends on data volume and the endpoint's cost.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

# No page-size name list. We test EVERY numeric query param and let behaviour
# decide: a param is a page-size control only if raising it demonstrably returns
# MORE items (a filter would not) — then, if the absurd value isn't clamped, it's
# unbounded. Names are never inspected.
_ABSURD = 1_000_000
_MAX_ROUTES = 60


@module("resource-consumption", "Unrestricted Resource Consumption")
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    page_targets = _pagination_targets(ctx)
    bulk_targets = _bulk_targets(ctx)

    if not page_targets and not bulk_targets:
        ctx.note("resource-consumption: no numeric query params or array-body endpoints")
        return

    uncapped: list[dict] = []
    probed = 0
    for route, param in page_targets[:_MAX_ROUTES]:
        probed += 1
        rec = _probe_pagination(ctx, route, param, token)
        if rec:
            uncapped.append(rec)

    ctx.note(f"resource-consumption: probed {probed} numeric query param(s), "
             f"{len(uncapped)} control result-size with no maximum; "
             f"{len(bulk_targets)} array-body endpoint(s) checked for maxItems")
    _report(ctx, uncapped, bulk_targets, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery ────────────────────────────────────────────────────────────────

def _pagination_targets(ctx: Context) -> list[tuple]:
    """Every numeric query param on a GET (structural: schema type, not name)."""
    out, seen = [], set()
    for r in ctx.routes:
        if r.method != "GET":
            continue
        for p in r.query_params:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            ptype = (p.get("schema") or {}).get("type")
            if name and ptype in ("integer", "number", None) \
                    and (r.key, name) not in seen:
                seen.add((r.key, name))
                out.append((r, name))
    return out


def _bulk_targets(ctx: Context) -> list[dict]:
    """Array request bodies with no maxItems — a static (no-traffic) check."""
    out = []
    for r in ctx.routes:
        if r.method not in ("POST", "PUT", "PATCH"):
            continue
        schema = r.body_schema or {}
        # top-level array body, or an array property with no maxItems
        if schema.get("type") == "array" and "maxItems" not in schema:
            out.append({"route": r, "field": "(body)"})
            continue
        for name, sub in (schema.get("properties", {}) or {}).items():
            if isinstance(sub, dict) and sub.get("type") == "array" \
                    and "maxItems" not in sub:
                out.append({"route": r, "field": name})
    return out


# ── probing ──────────────────────────────────────────────────────────────────

def _probe_pagination(ctx, route, param, token) -> dict | None:
    path = route.fill_path({p: "1" for p in route.path_params})
    try:
        low = ctx.get(path, params={param: 1}, token=token, timeout=10,
                      retry_429=False)
        huge = ctx.get(path, params={param: _ABSURD}, token=token, timeout=15,
                       retry_429=False)
    except requests.RequestException:
        return None
    if low.status_code >= 400:
        return None
    c_low, c_high = _count(low), _count(huge)
    # Behavioural proof of a page-size control: a larger value returns MORE items
    # (a filter/other numeric param would not), AND the absurd value is accepted
    # rather than clamped/rejected → no server-side maximum. This never inspects
    # the parameter's name.
    if (c_low is not None and c_high is not None and c_high > c_low
            and huge.status_code < 400):
        return {"route": route, "param": param, "base_items": c_low,
                "huge_items": c_high, "huge_bytes": len(huge.content)}
    return None


def _count(resp) -> int | None:
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return None
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for k in ("items", "results", "data", "objects", "records"):
            if isinstance(data.get(k), list):
                return len(data[k])
    return None


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx: Context, uncapped: list[dict], bulk: list[dict], probed: int) -> None:
    if uncapped:
        lead = uncapped[0]
        r = lead["route"]
        lines = []
        for x in uncapped[:15]:
            xr = x["route"]
            ic = f", returned {x['huge_items']} items" if x["huge_items"] is not None else ""
            lines.append(f"  {xr.method} {xr.path}  ?{x['param']}={_ABSURD} → HTTP<400"
                         f"{ic} ({x['huge_bytes']} bytes)")
        ctx.finding(
            id="a04-unbounded-pagination",
            owasp="A04", severity="MEDIUM",
            title=(f"No maximum page size on {r.method} {r.path} ('{lead['param']}')"
                   + (f" (+{len(uncapped) - 1} more)" if len(uncapped) > 1 else "")),
            summary=(
                f"The page-size parameter '{lead['param']}' accepts an absurd value "
                f"({_ABSURD}) without rejection or clamping — no server-side "
                "maximum is enforced. Against a populated table this streams the "
                "entire dataset to the caller in one request: a cheap "
                "denial-of-service and, on metered infrastructure, a "
                "cost-amplification attack. Enforce a hard cap "
                "(`Query(default=20, le=100)`) and reject or clamp oversized values."
            ),
            evidence="\n".join(lines),
            route=f"{r.method} {r.path}",
            request=f"GET {r.path}?{lead['param']}={_ABSURD}",
            reproduction=(f"GET {r.path}?{lead['param']}={_ABSURD}; it returns 2xx "
                          "instead of a 422, so no upper bound is enforced."),
            references=[REFS["A04"], REFS["api4"]],
            tools=["Burp Suite (Intruder)", "curl"],
        )

    if bulk:
        lead = bulk[0]
        r = lead["route"]
        lines = [f"  {b['route'].method} {b['route'].path}  array '{b['field']}' "
                 "has no maxItems" for b in bulk[:15]]
        ctx.finding(
            id="a04-unbounded-bulk",
            owasp="A04", severity="LOW",
            title=(f"Array body without maxItems on {r.method} {r.path}"
                   + (f" (+{len(bulk) - 1} more)" if len(bulk) > 1 else "")),
            summary=(
                "A request body accepts an array with no declared maxItems bound. "
                "A caller can submit an arbitrarily large batch, forcing "
                "proportional server work (parsing, validation, per-item DB writes "
                "/ external calls) in one request — resource exhaustion. Add a "
                "maxItems constraint (Pydantic `Field(max_length=…)` on the list) "
                "and reject oversized batches early."
            ),
            evidence="\n".join(lines),
            route=f"{r.method} {r.path}",
            references=[REFS["A04"], REFS["api4"]],
            tools=["Burp Suite", "curl"],
        )

    if not uncapped and not bulk and probed:
        ctx.finding(
            id="a04-resource-consumption-safe",
            owasp="A04", severity="SAFE",
            title="Page-size parameters enforce a maximum",
            summary=(
                f"Sent an absurd page size ({_ABSURD}) to {probed} paginated "
                "endpoint(s); each rejected or clamped it, consistent with a "
                "server-side cap, and array bodies declared maxItems. "
                "Per-endpoint compute cost and global rate limiting still warrant "
                "review for the most expensive operations."
            ),
            references=[REFS["A04"], REFS["api4"]],
        )
