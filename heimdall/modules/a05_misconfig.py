"""A05 — Security Misconfiguration.

Generic, route-map driven so it runs against any FastAPI target:
  1. CORS: probe a reflected/`*` `Access-Control-Allow-Origin` combined with
     `Access-Control-Allow-Credentials: true` — the classic cross-site data-theft
     misconfiguration — plus a preflight OPTIONS to confirm.
  2. Security headers: GET a public and a JSON endpoint and report the response
     hardening headers (CSP, HSTS, X-Frame-Options, nosniff, …) that are absent.
  3. Docs/schema exposure: interactive `/docs`, `/redoc` and `/openapi.json`
     reachable without auth hand an attacker the whole attack surface.
  4. Verbose errors: malformed input that should 4xx/5xx must not return a
     framework stack trace / debug page; a versioned `Server` header leaks the stack.
  5. HTTP methods: report the `Allow` set advertised for the base resource.

Every network call is defensively wrapped; on error we `ctx.note` and move on.
"""

from __future__ import annotations

import uuid

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

# The arbitrary, attacker-controlled origins we test for reflection.
_EVIL_ORIGIN = "https://evil.example.com"

# Response headers that harden a browser-facing app. Missing ones are reported.
_SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

# Substrings that betray a leaked stack trace / framework debug page.
_TRACE_MARKERS = (
    "traceback (most recent call last)",
    'file "',
    "starlette.exceptions",
    "fastapi/routing.py",
    "werkzeug.debug",
    "django.views.debug",
    "<div class=\"traceback\"",
    "internal server error at",
)


@module("a05", "Security Misconfiguration")
def run(ctx: Context) -> None:
    _cors(ctx)
    _security_headers(ctx)
    _docs_exposure(ctx)
    _verbose_errors(ctx)
    _http_methods(ctx)


def _probe_path(ctx: Context) -> str:
    """A cheap, reliably-reachable path to bounce CORS/header probes off of."""
    if ctx.auth.login_path:
        return ctx.auth.login_path
    for p in ("/openapi.json", "/"):
        if p in ctx.profile.docs_paths or p == "/":
            return p
    return "/"


def _cors(ctx: Context) -> None:
    """Reflected / wildcard ACAO + credentials = cross-site data theft."""
    path = _probe_path(ctx)
    rand_origin = f"https://{uuid.uuid4().hex[:12]}.attacker.example"
    findings_made = False
    rate_limited = False

    for origin in (_EVIL_ORIGIN, rand_origin):
        try:
            resp = ctx.get(path, headers={"Origin": origin})
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"CORS probe of {path} with origin {origin} failed: {exc}")
            continue

        if resp.status_code == 429:
            rate_limited = True
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
        creds = acac == "true"
        evidence = (
            f"GET {path}\n"
            f"  Origin: {origin}\n"
            f"  <- Access-Control-Allow-Origin: {acao!r}\n"
            f"  <- Access-Control-Allow-Credentials: {acac or '(absent)'}"
        )
        repro = (
            f"curl -s -i -H 'Origin: {origin}' {ctx.base_url}{path} "
            "| grep -i access-control"
        )

        if acao == origin and creds:
            findings_made = True
            ctx.finding(
                id="a05-cors-reflected-credentialed",
                owasp="A05", severity="HIGH",
                title="CORS reflects an arbitrary origin with credentials allowed",
                summary=(
                    "The server echoes an attacker-supplied `Origin` into "
                    "`Access-Control-Allow-Origin` while also sending "
                    "`Access-Control-Allow-Credentials: true`. Any malicious site can "
                    "make credentialed cross-origin requests and read the response, "
                    "stealing authenticated data (session/cookie-backed responses)."
                ),
                evidence=evidence,
                reproduction=repro,
                references=[REFS["ps-cors"], REFS["A05"]],
                tools=["Burp Suite", "curl", "browser fetch({credentials:'include'})"],
            )
            break  # one arbitrary origin is enough to prove reflection
        if acao == origin and not creds:
            findings_made = True
            ctx.finding(
                id="a05-cors-reflected",
                owasp="A05", severity="MEDIUM",
                title="CORS reflects an arbitrary origin (without credentials)",
                summary=(
                    "The server reflects any supplied `Origin` into "
                    "`Access-Control-Allow-Origin`. Credentials are not allowed, so "
                    "cookie-backed data is not directly exposed, but non-credentialed "
                    "cross-origin reads of otherwise-restricted responses become possible."
                ),
                evidence=evidence,
                reproduction=repro,
                references=[REFS["ps-cors"], REFS["A05"]],
                tools=["Burp Suite", "curl"],
            )
            break
        if acao == "*":
            findings_made = True
            if creds:
                ctx.finding(
                    id="a05-cors-wildcard-credentialed",
                    owasp="A05", severity="MEDIUM",
                    title="CORS wildcard origin combined with credentials",
                    summary=(
                        "`Access-Control-Allow-Origin: *` is sent alongside "
                        "`Access-Control-Allow-Credentials: true`. This is a broken policy, "
                        "but NOT directly exploitable: browsers reject the literal `*` + "
                        "credentials combination and won't expose the response to JS. The "
                        "genuinely exploitable variant is a REFLECTED origin + credentials "
                        "(reported separately as HIGH). Fix the policy — pin explicit "
                        "origins — and verify this reflects your production CORS config, "
                        "not just a permissive dev setting."
                    ),
                    evidence=evidence,
                    reproduction=repro,
                    references=[REFS["ps-cors"], REFS["A05"]],
                    tools=["Burp Suite", "curl"],
                )
            else:
                ctx.finding(
                    id="a05-cors-wildcard",
                    owasp="A05", severity="LOW",
                    title="CORS allows any origin (wildcard)",
                    summary=(
                        "`Access-Control-Allow-Origin: *` lets any website read "
                        "non-credentialed responses from this endpoint. Acceptable for "
                        "truly public data, but a risk if any reachable route returns "
                        "sensitive information without authentication."
                    ),
                    evidence=evidence,
                    reproduction=repro,
                    references=[REFS["ps-cors"], REFS["A05"]],
                    tools=["curl"],
                )
            break

    # Preflight confirmation — attach the reflected header set as evidence.
    try:
        pre = ctx.request(
            "OPTIONS", path,
            headers={
                "Origin": _EVIL_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        acao = pre.headers.get("Access-Control-Allow-Origin")
        if acao in (_EVIL_ORIGIN, "*"):
            ctx.note(
                f"CORS preflight OPTIONS {path} -> {pre.status_code}; "
                f"ACAO={acao!r} "
                f"ACAC={pre.headers.get('Access-Control-Allow-Credentials')!r} "
                f"ACAM={pre.headers.get('Access-Control-Allow-Methods')!r}"
            )
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"CORS preflight OPTIONS {path} failed: {exc}")

    if not findings_made and rate_limited:
        ctx.finding(
            id="a05-cors-reflected",
            owasp="A05", severity="INFO",
            title="CORS check inconclusive — target rate-limited the probe (429)",
            summary=(
                "The CORS probes were answered with HTTP 429 even after back-off, so "
                "reflection could not be determined. Re-run this check in isolation "
                "(`--only a05`) or after the rate-limit window resets."
            ),
        )
    elif not findings_made:
        ctx.finding(
            id="a05-cors-reflected",
            owasp="A05", severity="SAFE",
            title="CORS does not reflect arbitrary origins",
            summary=(
                "Requests carrying attacker-controlled `Origin` headers did not receive "
                "a matching (or wildcard-with-credentials) "
                "`Access-Control-Allow-Origin`, so cross-site read of authenticated "
                "responses is not enabled by the CORS policy."
            ),
        )


def _security_headers(ctx: Context) -> None:
    """One consolidated finding listing absent browser-hardening headers."""
    https = ctx.base_url.lower().startswith("https")
    targets = ["/"]
    json_path = None
    for p in ("/openapi.json", ctx.auth.me_path, ctx.auth.login_path):
        if p and p not in targets:
            json_path = p
            targets.append(p)
            break

    seen_any = False
    missing: set[str] = set()
    present: dict[str, str] = {}
    header_dump = ""

    for path in targets:
        try:
            resp = ctx.get(path)
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"security-header probe of {path} failed: {exc}")
            continue
        seen_any = True
        if not header_dump:
            header_dump = "\n".join(
                f"  {k}: {v}" for k, v in resp.headers.items()
            ) or "  (no response headers)"
        for h in _SECURITY_HEADERS:
            val = resp.headers.get(h)
            if val:
                present[h] = val
            elif h not in present:
                missing.add(h)

    if not seen_any:
        ctx.note("security-header probe: no endpoint responded; skipped")
        return

    # HSTS is only meaningful over HTTPS — don't fault a plain-HTTP test target.
    hsts_missing = "Strict-Transport-Security" in missing
    if not https and hsts_missing:
        missing.discard("Strict-Transport-Security")

    # X-Frame-Options is satisfied by a CSP frame-ancestors directive.
    csp = present.get("Content-Security-Policy", "").lower()
    if "frame-ancestors" in csp:
        missing.discard("X-Frame-Options")

    xfo_absent = "X-Frame-Options" in missing
    frame_ancestors_absent = "frame-ancestors" not in csp
    clickjacking = xfo_absent and frame_ancestors_absent

    if missing:
        ordered = [h for h in _SECURITY_HEADERS if h in missing]
        summary = (
            "Common response-hardening headers are absent, leaving browser-side "
            "defences (framing, MIME sniffing, transport pinning, referrer/permission "
            "policy) to their weak defaults. Missing: " + ", ".join(ordered) + "."
        )
        if clickjacking:
            summary += (
                " Neither X-Frame-Options nor a CSP `frame-ancestors` directive is "
                "present, so any page rendered by this app can be framed — clickjacking risk."
            )
        if not https:
            summary += (
                " (Target is plain HTTP; Strict-Transport-Security only applies over "
                "HTTPS and was excluded.)"
            )
        # Content-Security-Policy / clickjacking gaps carry more weight than the rest.
        sev = "MEDIUM" if ("Content-Security-Policy" in missing or clickjacking) else "LOW"
        ctx.finding(
            id="a05-missing-security-headers",
            owasp="A05", severity=sev,
            title=f"{len(ordered)} security response header(s) missing",
            summary=summary,
            evidence=f"Response headers observed:\n{header_dump}",
            reproduction=f"curl -s -i {ctx.base_url}/ | grep -iE "
                         "'content-security|strict-transport|x-frame|x-content-type|"
                         "referrer-policy|permissions-policy'",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                REFS["A05"],
            ],
            tools=["curl", "securityheaders.com", "Mozilla Observatory"],
        )
    else:
        ctx.finding(
            id="a05-missing-security-headers",
            owasp="A05", severity="SAFE",
            title="Browser-hardening response headers present",
            summary="All checked hardening headers (CSP, X-Frame-Options/frame-ancestors, "
                    "nosniff, Referrer-Policy, Permissions-Policy"
                    + (", HSTS" if https else "")
                    + ") were served.",
        )


def _docs_exposure(ctx: Context) -> None:
    """Unauthenticated interactive docs / schema map the attack surface."""
    exposed = list(ctx.profile.docs_paths or [])
    if not exposed:
        # Nothing was discovered as publicly reachable — probe the usual suspects.
        for p in ("/docs", "/redoc", "/openapi.json"):
            try:
                resp = ctx.get(p)
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"docs probe of {p} failed: {exc}")
                continue
            if resp.status_code < 300 and p not in exposed:
                exposed.append(p)

    interactive = [p for p in exposed if any(s in p for s in ("/docs", "/redoc"))]
    schema = [p for p in exposed if "openapi" in p]

    if exposed:
        sev = "LOW" if interactive else "INFO"
        ctx.finding(
            id="a05-docs-exposed",
            owasp="A05", severity=sev,
            title="API documentation / schema reachable without authentication",
            summary=(
                "Interactive docs and/or the OpenAPI schema are served to anonymous "
                "callers, disclosing the full route inventory, parameter shapes and "
                "auth requirements — a ready-made map of the attack surface. Consider "
                "gating these behind auth or disabling them in production."
            ),
            evidence="Exposed: " + ", ".join(exposed)
                     + (f"\n  interactive: {', '.join(interactive)}" if interactive else "")
                     + (f"\n  schema: {', '.join(schema)}" if schema else ""),
            reproduction=f"curl -s {ctx.base_url}{exposed[0]}",
            references=[REFS["A05"]],
            tools=["curl", "browser"],
        )
    else:
        ctx.finding(
            id="a05-docs-exposed",
            owasp="A05", severity="SAFE",
            title="No unauthenticated API docs / schema exposure",
            summary="Interactive docs (/docs, /redoc) and /openapi.json were not reachable "
                    "without authentication.",
        )


def _verbose_errors(ctx: Context) -> None:
    """Malformed input must not leak a stack trace / debug page."""
    leaked = None

    # 1. Break the login schema (wrong types where the body expects strings).
    login = ctx.auth.login_path
    if login:
        for body in ({"__heimdall__": {"nested": [1, 2, 3]}}, "not-json-at-all"):
            try:
                if isinstance(body, str):
                    resp = ctx.post(login, data=body,
                                    headers={"Content-Type": "application/json"})
                else:
                    resp = ctx.post(login, json=body)
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"verbose-error probe of {login} failed: {exc}")
                continue
            if _has_trace(resp.text):
                leaked = (f"POST {login}", resp)
                break

    # 2. Type-confuse an int-looking path param on a GET route.
    if leaked is None:
        for r in ctx.routes:
            if r.method != "GET" or len(r.path_params) != 1:
                continue
            pname = r.path_params[0]
            probe = r.fill_path({pname: "heimdall'\"<>"})
            try:
                resp = ctx.get(probe)
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"verbose-error probe of {probe} failed: {exc}")
                continue
            if _has_trace(resp.text):
                leaked = (f"GET {probe}", resp)
                break

    if leaked is not None:
        where, resp = leaked
        snippet = resp.text[:800]
        ctx.finding(
            id="a05-verbose-error",
            owasp="A05", severity="HIGH",
            title="Server returns a stack trace / debug page on malformed input",
            summary=(
                "Malformed input triggered a response containing a framework stack trace "
                "or debug page. This indicates debug mode is enabled (or errors are not "
                "handled) and leaks source paths, library versions and internal logic that "
                "accelerate further exploitation."
            ),
            evidence=f"{where} -> {resp.status_code}\n---\n{snippet}",
            reproduction=f"Send malformed/typed-wrong input to {where.split(' ', 1)[1]} "
                         "and observe the traceback in the response body.",
            references=[REFS["A05"]],
            tools=["curl", "Burp Suite"],
        )
    else:
        ctx.finding(
            id="a05-verbose-error",
            owasp="A05", severity="SAFE",
            title="No stack traces leaked on malformed input",
            summary="Schema-violating and type-confused requests returned handled error "
                    "responses without a framework traceback or debug page.",
        )

    # Disclosive Server header (versioned stack) — informational.
    try:
        resp = ctx.get("/")
        server = resp.headers.get("Server", "")
        low = server.lower()
        if server and any(t in low for t in ("uvicorn", "gunicorn", "hypercorn",
                                             "python", "werkzeug")) and any(
                ch.isdigit() for ch in server):
            ctx.finding(
                id="a05-server-banner",
                owasp="A05", severity="INFO",
                title="Server header discloses the application stack/version",
                summary=(
                    "The `Server` response header names the ASGI/WSGI server (and a "
                    "version), helping an attacker match known CVEs to the deployment. "
                    "Strip or genericise the banner at the edge/proxy."
                ),
                evidence=f"Server: {server}",
                reproduction=f"curl -s -I {ctx.base_url}/ | grep -i '^server:'",
                references=[REFS["A05"], REFS["A06"]],
                tools=["curl"],
            )
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"server-banner probe failed: {exc}")


def _http_methods(ctx: Context) -> None:
    """Light touch: report the Allow set advertised for the base resource."""
    try:
        resp = ctx.request("OPTIONS", "/")
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"OPTIONS / probe failed: {exc}")
        return
    allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods")
    if allow:
        ctx.note(f"OPTIONS / -> {resp.status_code}; advertised methods: {allow}")
        if "TRACE" in allow.upper():
            ctx.finding(
                id="a05-http-trace",
                owasp="A05", severity="LOW",
                title="HTTP TRACE method advertised",
                summary=(
                    "The server advertises the TRACE method, which reflects the request "
                    "back to the client and has historically enabled Cross-Site Tracing "
                    "(XST). It should be disabled at the server/proxy."
                ),
                evidence=f"OPTIONS / -> {resp.status_code}\n  Allow: {allow}",
                reproduction=f"curl -s -i -X OPTIONS {ctx.base_url}/ | grep -i allow",
                references=[REFS["A05"]],
                tools=["curl"],
            )


def _has_trace(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    return any(marker in t for marker in _TRACE_MARKERS)
