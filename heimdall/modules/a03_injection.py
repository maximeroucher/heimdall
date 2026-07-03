"""A03 — Injection (SQLi / XSS / operator injection).

Fully route-map driven, so it works on any FastAPI target:
  1. SQL injection: every GET route that declares query params is fuzzed one
     param at a time with classic SQLi payloads, compared against a benign
     baseline. A SQL error signature in the body is a strong signal; a payload
     that turns a 200 baseline into a 500 is a weaker "possible" signal.
  2. Reflected XSS: JSON-body write routes get a unique ``<script>`` marker in
     each string field; if the raw marker comes back un-encoded the app echoes
     attacker HTML without output encoding (verify at the render sink).
  3. Operator injection (light): login/filter-ish JSON routes get a Mongo-style
     ``{"$ne": null}`` where a string is expected, to spot NoSQL operator
     injection or auth bypass.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import body_says_error, module

# Classic SQLi probes. Each is sent one query-param at a time; the pg_sleep one
# is harmless (0-second sleep) but still exercises stacked-query parsing.
_SQLI_PROBES = ["'", "' OR '1'='1", "1;SELECT pg_sleep(0)--", "%27", "\" OR \"1\"=\"1"]
# A value that should never itself trigger a server error — the baseline.
_BENIGN = "heimdallbaseline1"
# Routes that legitimately reflect user input (search/echo) or are noisy to
# fuzz; still fuzzed, but this keeps caps meaningful.
_SQLI_ROUTE_CAP = 40
_SQLI_PARAM_CAP = 3
_XSS_ROUTE_CAP = 25
# NoSQL operator-injection hint: routes that look like auth or filtering.
_OPINJ_HINT = ("login", "token", "auth", "signin", "search", "filter", "query", "find")


@module("a03", "Injection (SQLi / XSS)")
def run(ctx: Context) -> None:
    _sqli_sweep(ctx)
    _xss_probe(ctx)
    _operator_injection(ctx)


def _actor_token(ctx: Context) -> str | None:
    """Prefer a low-privilege attacker token, else any authed principal."""
    p = ctx.principal("attacker", "user")
    if p and p.authed:
        return p.token
    any_p = ctx.profile.any_authed()
    return any_p.token if any_p else None


def _sqli_sweep(ctx: Context) -> None:
    """Fuzz query params of GET routes with SQLi payloads vs. a baseline."""
    token = _actor_token(ctx)
    targets = [r for r in ctx.routes.by_method("GET") if r.query_params][:_SQLI_ROUTE_CAP]
    if not targets:
        ctx.note("no GET routes with query params; SQLi sweep skipped")
        return

    error_hits = []   # strong: SQL error signature leaked
    err500_hits = []  # weak: payload caused a 500 the baseline did not
    tested = 0
    for r in targets:
        for param in r.query_params[:_SQLI_PARAM_CAP]:
            pname = param.get("name")
            if not pname:
                continue
            # Baseline first so we can tell "always 500" from "500 on injection".
            try:
                base = ctx.get(r.fill_path({}), token=token, params={pname: _BENIGN})
            except Exception as exc:  # requests may raise on connection issues
                ctx.note(f"baseline request failed for GET {r.path}?{pname}: {exc}")
                continue
            base_500 = base.status_code >= 500
            tested += 1
            for probe in _SQLI_PROBES:
                try:
                    resp = ctx.get(r.fill_path({}), token=token, params={pname: probe})
                except Exception as exc:
                    ctx.note(f"probe failed for GET {r.path}?{pname}: {exc}")
                    continue
                if body_says_error(resp.text):
                    error_hits.append((r, pname, probe, resp))
                    break  # one strong signal per param is enough
                if resp.status_code >= 500 and not base_500:
                    err500_hits.append((r, pname, probe, resp))
                    break

    if error_hits:
        sample = "\n".join(
            f"  GET {r.path}?{pname}={probe!r} -> {resp.status_code} (SQL error leaked)"
            for r, pname, probe, resp in error_hits[:15]
        )
        r0, p0, pr0, _ = error_hits[0]
        ctx.finding(
            id="a03-sqli-error-based",
            owasp="A03", severity="HIGH",
            title=f"Error-based SQL injection signal on {len(error_hits)} param(s)",
            summary=(
                "Injecting SQL metacharacters into query parameters produced database "
                "error signatures (SQLAlchemy/psycopg/syntax errors) in the response body. "
                "Unsanitised input is reaching the SQL layer — a likely injection point "
                "and, at minimum, verbose error leakage. Confirm with a boolean/time-based "
                "payload before reporting exploitability."
            ),
            evidence=sample,
            reproduction=(
                f"curl -s '{ctx.base_url}{r0.fill_path({})}?{p0}={pr0}'"
                "  # observe SQL error in body"
            ),
            references=[REFS["ps-sqli"], REFS["A03"]],
            tools=["sqlmap", "Burp Suite (Intruder)", "curl"],
        )
    elif err500_hits:
        sample = "\n".join(
            f"  GET {r.path}?{pname}={probe!r} -> {resp.status_code} (baseline was <500)"
            for r, pname, probe, resp in err500_hits[:15]
        )
        r0, p0, pr0, _ = err500_hits[0]
        ctx.finding(
            id="a03-sqli-possible",
            owasp="A03", severity="MEDIUM",
            title=f"Possible SQL injection on {len(err500_hits)} param(s) (500 on payload)",
            summary=(
                "SQL metacharacters in these query parameters produced a 500 that a benign "
                "baseline value did not, suggesting the input reaches an unsanitised query "
                "path. No explicit SQL error signature was leaked, so this is a candidate "
                "rather than a confirmed injection — verify with sqlmap."
            ),
            evidence=sample,
            reproduction=(
                f"curl -s '{ctx.base_url}{r0.fill_path({})}?{p0}={pr0}'"
                "  # 500 vs. benign baseline"
            ),
            references=[REFS["ps-sqli"], REFS["A03"]],
            tools=["sqlmap", "Burp Suite (Intruder)", "curl"],
        )
    elif tested:
        ctx.finding(
            id="a03-sqli-error-based",
            owasp="A03", severity="SAFE",
            title="No SQL injection signal on fuzzed query params",
            summary=(
                f"Fuzzed {tested} query param(s) across up to {len(targets)} GET route(s) "
                "with classic SQLi payloads; none leaked a SQL error or diverged from the "
                "benign baseline status."
            ),
        )


def _xss_probe(ctx: Context) -> None:
    """Send a unique <script> marker into string body fields; flag raw reflection."""
    if ctx.safe:
        ctx.note("safe mode: skipping mutating XSS reflection probe")
        return
    token = _actor_token(ctx)
    targets = [
        r for r in ctx.routes.by_method("POST", "PUT", "PATCH")
        if body_field_names(r)
    ][:_XSS_ROUTE_CAP]
    if not targets:
        ctx.note("no JSON-body write routes; XSS probe skipped")
        return

    reflected = []
    for n, r in enumerate(targets):
        fields = body_field_names(r)
        marker = f"heimallmarker{n}"
        payload = f"<script>heimdall{n}</script>"
        # Fill every field with the payload; string typing is best-effort here,
        # non-string fields simply get rejected by validation (harmless).
        body = {f: payload for f in fields}
        body["_heimdall_marker"] = marker  # extra field, ignored by most schemas
        try:
            resp = ctx.request(r.method, r.fill_path({}), token=token, json=body)
        except Exception as exc:
            ctx.note(f"XSS probe failed for {r.method} {r.path}: {exc}")
            continue
        # Raw, un-encoded reflection of the <script> tag is the signal; an
        # HTML-encoded (&lt;script&gt;) echo is safe and does not match.
        if payload in resp.text:
            reflected.append((r, payload, resp))

    if reflected:
        sample = "\n".join(
            f"  {r.method} {r.path} -> {resp.status_code} (reflected {payload!r} raw)"
            for r, payload, resp in reflected[:15]
        )
        r0 = reflected[0][0]
        ctx.finding(
            id="a03-xss-reflected",
            owasp="A03", severity="MEDIUM",
            title=f"Un-encoded input reflected on {len(reflected)} write route(s)",
            summary=(
                "A unique <script> payload submitted in the request body was echoed back "
                "verbatim, without HTML-encoding, in the response. The value was persisted "
                "or reflected without server-side output encoding — verify at the render "
                "sink (any HTML page/template that displays this field) to confirm "
                "reflected or stored XSS. JSON API responses are only exploitable if a "
                "browser renders them as HTML."
            ),
            evidence=sample,
            reproduction=(
                f"Submit {r0.method} {r0.path} with a body field set to "
                "'<script>alert(1)</script>' and inspect where the value is rendered."
            ),
            references=[REFS["A03"]],
            tools=["Burp Suite (Intruder)", "XSS Hunter", "curl"],
        )
    else:
        ctx.finding(
            id="a03-xss-reflected",
            owasp="A03", severity="SAFE",
            title="No raw HTML reflection on write routes",
            summary=(
                f"Submitted a <script> marker to {len(targets)} JSON-body write route(s); "
                "none reflected the payload un-encoded in the response body."
            ),
        )


def _operator_injection(ctx: Context) -> None:
    """Light NoSQL/operator-injection probe on auth/filter JSON routes."""
    if ctx.safe:
        ctx.note("safe mode: skipping mutating operator-injection probe")
        return
    targets = [
        r for r in ctx.routes.by_method("POST", "PUT", "PATCH")
        if body_field_names(r)
        and any(h in f"{r.path} {r.operation_id}".lower() for h in _OPINJ_HINT)
    ][:15]
    if not targets:
        ctx.note("no auth/filter JSON routes; operator-injection probe skipped")
        return

    hits = []
    for r in targets:
        fields = body_field_names(r)
        # Baseline: a normal (wrong) string value — establishes the reject status.
        benign = {f: _BENIGN for f in fields}
        # Injection: swap each field for a Mongo-style operator object.
        operator = {f: {"$ne": None} for f in fields}
        try:
            base = ctx.request(r.method, r.fill_path({}), json=benign)
            inj = ctx.request(r.method, r.fill_path({}), json=operator)
        except Exception as exc:
            ctx.note(f"operator-injection probe failed for {r.method} {r.path}: {exc}")
            continue
        # Signals: a 500 (operator reached a query engine) or a 200 where the
        # benign value was rejected (auth/filter bypass).
        if inj.status_code >= 500:
            hits.append((r, base, inj, "500 on operator object"))
        elif inj.status_code < 300 and base.status_code in (400, 401, 403, 422):
            hits.append((r, base, inj, "bypass: operator accepted where benign was rejected"))

    if hits:
        sample = "\n".join(
            f"  {r.method} {r.path} -> {inj.status_code} (baseline {base.status_code}; {why})"
            for r, base, inj, why in hits[:15]
        )
        r0 = hits[0][0]
        ctx.finding(
            id="a03-operator-injection",
            owasp="A03", severity="HIGH",
            title=f"Operator injection signal on {len(hits)} route(s)",
            summary=(
                "Submitting a Mongo-style operator object ({\"$ne\": null}) where a string "
                "was expected either errored the backend or was accepted where a benign "
                "value was rejected. This indicates the body is passed into a query/filter "
                "without type validation — NoSQL operator injection or an authentication "
                "bypass. Confirm manually before reporting."
            ),
            evidence=sample,
            reproduction=(
                f"Send {r0.method} {r0.path} with a string field replaced by "
                "'{\"$ne\": null}' and compare against a benign value."
            ),
            references=[REFS["A03"]],
            tools=["Burp Suite (Repeater)", "NoSQLMap", "curl"],
        )
    else:
        ctx.finding(
            id="a03-operator-injection",
            owasp="A03", severity="SAFE",
            title="No operator-injection signal on auth/filter routes",
            summary=(
                f"Sent a {{\"$ne\": null}} operator object to {len(targets)} auth/filter "
                "route(s); none errored or bypassed validation."
            ),
        )
