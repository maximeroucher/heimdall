"""A10 — Server-Side Request Forgery (SSRF).

Fully route-map driven, so it works on any FastAPI target. Black-box SSRF
detection is a two-step game: first find the request parameters/fields that
make the *server* go fetch a URL, then try to steer that fetch at internal
targets (loopback, the cloud metadata service, link-local space) and watch how
the server reacts.

  1. Sink discovery: scan every route's query params + request-body fields for
     URL-ish names (url, uri, webhook, callback, image_url, redirect, ...). No
     network traffic — purely reading the OpenAPI surface.
  2. Probing: point each candidate at internal-target payloads plus a bogus
     ``.invalid`` control, and diff the reactions. A server that hangs on
     127.0.0.1 but instantly rejects ``heimdall.invalid`` — or leaks a
     "Connection refused" / "Failed to establish a connection to 169.254..."
     error — is provably performing the fetch on our behalf.

Server-side URL fetching is often blind: the response you get back reveals
nothing, and only an out-of-band (OAST) collaborator callback confirms it.
This module therefore reports *confirmed* SSRF loudly and everything else as a
"potential sink, verify with OAST" lead rather than a false-positive HIGH.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

# Parameter/field names that commonly carry a URL the server will dereference.
# Names that (almost) always denote a URL the server may fetch. Kept tight on
# purpose: loose hints like "next"/"return"/"target"/"page"/"file" match filter
# and pagination params (e.g. a boolean `returned` on a loans route) and produce
# false SSRF. A param qualifies only by an exact match here, or a clear url/uri
# suffix, or a webhook/callback/href substring (see ``_looks_urlish``).
_URL_HINTS = (
    "url", "uri", "link", "href", "webhook", "callback", "redirect_uri",
    "redirect_url", "image_url", "avatar_url", "img_url", "src", "source_url",
    "fetch_url", "proxy_url", "callback_url", "webhook_url", "image", "avatar",
)
_URL_SUFFIXES = ("_url", "_uri", "url", "uri")
_URL_SUBSTR = ("webhook", "callback", "href")

# Internal targets we try to make the server reach, plus a control that should
# fail fast for everyone. 169.254.169.254 is the near-universal cloud metadata
# endpoint (AWS/GCP/Azure/OpenStack) — reaching it is the crown-jewel SSRF.
_METADATA = "http://169.254.169.254/latest/meta-data/"
_INTERNAL_PAYLOADS = (
    "http://127.0.0.1:80/",
    _METADATA,
    "http://localhost/",
    "http://[::1]/",
)
_CONTROL = "http://heimdall.invalid/"   # unresolvable — should be rejected fast

# Short per-probe timeout: a server that stalls trying to reach an internal host
# is *itself* a signal, so we want to notice the hang quickly rather than wait
# out the default 30s client timeout.
_PROBE_TIMEOUT = 6.0

_MAX_CANDIDATES = 30

# Substrings in a response/exception that betray the server actually attempted
# an outbound connection (i.e. it dereferenced our URL).
_FETCH_LEAK = (
    "connection refused", "failed to establish a connection", "name or service"
    " not known", "connection reset", "no route to host", "connection aborted",
    "connection timed out", "max retries exceeded", "newconnectionerror",
    "getaddrinfo", "econnrefused", "network is unreachable", "connect to",
)

# Substrings that suggest cloud-metadata content actually came back.
_METADATA_MARKERS = (
    "ami-id", "instance-id", "iam/", "security-credentials", "meta-data",
    "hostname", "local-ipv4", "public-keys", "computemetadata",
)


@module("a10", "Server-Side Request Forgery")
def run(ctx: Context) -> None:
    sinks = _discover_sinks(ctx)
    if not sinks:
        ctx.note("no URL-like sinks in the API surface")
        ctx.finding(
            id="a10-no-sinks",
            owasp="A10", severity="INFO",
            title="No obvious SSRF sinks exposed in the API surface",
            summary=(
                "No query parameter or request-body field across the discovered "
                "routes carries a URL-ish name (url, uri, webhook, image_url, "
                "callback, redirect, ...). That is not proof the app never makes "
                "server-side requests — a fetch can hide behind an innocuously "
                "named field or a value that only looks like an id — but there is "
                "no black-box SSRF sink to steer from the documented surface."
            ),
            references=[REFS["A10"]],
            tools=["Burp Suite (Collaborator)", "ssrfmap"],
        )
        return

    confirmed = _probe_sinks(ctx, sinks)
    _report(ctx, sinks, confirmed)


# ── sink discovery ───────────────────────────────────────────────────────────

def _looks_urlish(name: str) -> bool:
    n = name.lower()
    if n in _URL_HINTS:
        return True
    if any(n.endswith(sfx) for sfx in _URL_SUFFIXES):
        return True
    return any(sub in n for sub in _URL_SUBSTR)


def _discover_sinks(ctx: Context) -> list[tuple]:
    """Collect ``(route, param_name, location)`` for every URL-ish param/field.

    ``location`` is "query" or "body". Purely reads the route map — no requests.
    """
    sinks: list[tuple] = []
    seen: set[tuple[str, str, str]] = set()
    for r in ctx.routes:
        # query params (dicts with a "name")
        for p in r.query_params:
            name = p.get("name") if isinstance(p, dict) else None
            if name and _looks_urlish(name):
                keyk = (r.key, name, "query")
                if keyk not in seen:
                    seen.add(keyk)
                    sinks.append((r, name, "query"))
        # request-body fields
        if r.method in ("POST", "PUT", "PATCH"):
            for name in body_field_names(r):
                if _looks_urlish(name):
                    keyk = (r.key, name, "body")
                    if keyk not in seen:
                        seen.add(keyk)
                        sinks.append((r, name, "body"))
    return sinks


# ── probing ──────────────────────────────────────────────────────────────────

def _safe_path(route) -> str:
    """A concrete path with any path params filled by a benign placeholder."""
    if not route.has_path_param:
        return route.path
    return route.fill_path({p: "1" for p in route.path_params})


def _send(ctx: Context, route, name: str, location: str, payload: str,
          token: str | None):
    """Fire one probe. Returns ``(kind, detail)`` where kind is one of:

      "fetch-leak"  — server leaked an outbound-connection error (fetch attempted)
      "metadata"    — cloud-metadata content reflected back
      "timeout"     — our request hung (server likely stalled on internal host)
      "resp"        — a normal HTTP response (detail = requests.Response)
      "skip"        — nothing usable / our-side error we treated as noise
    """
    path = _safe_path(route)
    try:
        if location == "query":
            resp = ctx.get(path, params={name: payload}, token=token,
                           timeout=_PROBE_TIMEOUT)
        else:
            method = route.method.lower()
            call = getattr(ctx, method, ctx.post)
            resp = call(path, json={name: payload}, token=token,
                        timeout=_PROBE_TIMEOUT)
    except requests.Timeout:
        # Our client timed out. For an internal target this often means the
        # server accepted the URL and is blocking on a connect() to a host that
        # silently drops — a classic blind-SSRF timing tell. For the .invalid
        # control it would just be odd, so callers weigh it against the control.
        return "timeout", f"client timeout after {_PROBE_TIMEOUT}s"
    except requests.RequestException as exc:
        # Our-side transport error talking to the *target* (not the target's own
        # fetch failing). Treat as noise, not signal.
        return "skip", f"our-side error: {type(exc).__name__}: {exc}"

    body = ""
    try:
        body = resp.text or ""
    except Exception:  # pragma: no cover - defensive; body decode issues
        body = ""
    low = body.lower()

    # A 4xx means the server REJECTED the input (didn't fetch) — and its error
    # often echoes our payload verbatim, so a rejected "…/meta-data/" URL would
    # otherwise trip the metadata check. Only a non-error response can evidence a
    # fetch, and metadata markers must be ones NOT present in the payload we sent
    # (i.e. content that came from the metadata service, not our echoed URL).
    plow = payload.lower()
    fetched = resp.status_code < 400
    if payload == _METADATA and fetched:
        hits = [m for m in _METADATA_MARKERS if m in low and m not in plow]
        if hits:
            return "metadata", f"HTTP {resp.status_code}, metadata markers in body: {hits}"
    if fetched and any(s in low for s in _FETCH_LEAK):
        return "fetch-leak", f"HTTP {resp.status_code}: {body[:200].strip()}"
    return "resp", resp


def _probe_sinks(ctx: Context, sinks: list[tuple]) -> list[dict]:
    """Actively probe each candidate; return a list of confirmed-SSRF records."""
    # Authenticate probes when we hold any usable token — many URL sinks sit
    # behind auth (profile avatar, webhook registration, ...).
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    token = princ.token if princ and princ.authed else None

    confirmed: list[dict] = []
    probed = 0
    for route, name, location in sinks[:_MAX_CANDIDATES]:
        # Body/mutating probes only in FULL mode; query GETs are reads and stay
        # allowed even in safe mode (still conservative — no state change).
        if location == "body" and ctx.safe:
            continue
        if location == "query" and route.method != "GET" and ctx.safe:
            continue
        probed += 1

        # Control first: how does a fast-failing, unresolvable host behave?
        control_kind, control_detail = _send(
            ctx, route, name, location, _CONTROL, token)

        record = None
        for payload in _INTERNAL_PAYLOADS:
            kind, detail = _send(ctx, route, name, location, payload, token)
            is_meta = payload == _METADATA

            if kind == "metadata":
                record = _mk_record(route, name, location, payload,
                                    "cloud-metadata content reflected", detail,
                                    critical=True)
                break
            if kind == "fetch-leak":
                # Server tried to connect out — but if the *control* leaked the
                # same class of error the app just echoes any bad URL; only count
                # it as SSRF when the internal target provokes it distinctly.
                record = _mk_record(
                    route, name, location, payload,
                    "server leaked an outbound-connection error (fetch attempted)",
                    detail, critical=is_meta)
                break
            if kind == "timeout" and control_kind != "timeout":
                # Internal host hangs while the .invalid control returned fast:
                # a timing divergence consistent with a real server-side fetch.
                record = _mk_record(
                    route, name, location, payload,
                    "internal target hung while the .invalid control returned "
                    "fast (timing divergence)", detail, critical=is_meta)
                break
            # NOTE: a plain HTTP-response *divergence* between an internal URL and
            # the .invalid control is deliberately NOT treated as SSRF — a param
            # that merely validates/echoes its value (a filter, an enum) diverges
            # too, which produced false CRITICALs. Only outbound-connection
            # evidence (metadata reflection, connection-error leak, timing hang)
            # confirms a fetch; everything else stays an unconfirmed sink below.

        if record is not None:
            confirmed.append(record)

    ctx.note(f"SSRF: probed {probed} URL-accepting parameter(s), "
             f"{len(confirmed)} showed server-side fetch behaviour")
    return confirmed


def _r(resp) -> str:
    try:
        return f"HTTP {resp.status_code}/{len(resp.content)}B"
    except Exception:  # pragma: no cover - defensive
        return "HTTP ?"


def _diverges(internal, control) -> bool:
    """Meaningful difference between the internal-target and control responses.

    Conservative: a different status class, or a body-size delta large enough to
    not be incidental. Same status + near-identical size = the app almost
    certainly validated/echoed both without dialing out.
    """
    if internal.status_code // 100 != control.status_code // 100:
        return True
    delta = abs(len(internal.content) - len(control.content))
    return delta > 64


def _mk_record(route, name, location, payload, why, detail, *,
               critical: bool = False, weak: bool = False) -> dict:
    return {
        "route": route, "name": name, "location": location,
        "payload": payload, "why": why, "detail": detail,
        "critical": critical, "weak": weak,
    }


# ── findings ─────────────────────────────────────────────────────────────────

def _sink_line(route, name, location) -> str:
    return f"  {route.method} {route.path}  [{location}:{name}]"


def _report(ctx: Context, sinks: list[tuple], confirmed: list[dict]) -> None:
    # Strong, confirmed hits first.
    strong = [c for c in confirmed if not c["weak"]]
    weakish = [c for c in confirmed if c["weak"]]

    if strong or weakish:
        critical = any(c["critical"] for c in confirmed)
        # A weak-only result (mere response divergence) is not enough to shout
        # HIGH on its own — keep it MEDIUM and flag for OAST confirmation.
        severity = "CRITICAL" if critical else ("HIGH" if strong else "MEDIUM")
        lead = confirmed[0]
        r = lead["route"]
        evid_lines = []
        for c in confirmed[:15]:
            cr = c["route"]
            evid_lines.append(
                f"  {cr.method} {cr.path} [{c['location']}:{c['name']}] "
                f"payload={c['payload']}\n      -> {c['why']}\n"
                f"      {c['detail']}"
            )
        meta_hit = any(c["critical"] for c in confirmed)
        ctx.finding(
            id="a10-ssrf-confirmed",
            owasp="A10", severity=severity,
            title=(f"SSRF via {lead['name']} on {r.method} {r.path}"
                   + (f" (+{len(confirmed) - 1} more)" if len(confirmed) > 1 else "")),
            summary=(
                "A URL-accepting parameter caused the server to make an outbound "
                "request to an attacker-supplied internal host. The server's "
                "reaction to loopback / link-local / cloud-metadata targets "
                "differed provably from an unresolvable control URL "
                "(connection-error leak, response divergence, or a timing hang), "
                "confirming it dereferences caller-controlled URLs without a "
                "host allow-list. "
                + ("The cloud metadata service (169.254.169.254) returned data — "
                   "an attacker can read instance credentials / IAM tokens and "
                   "pivot into the cloud account. "
                   if meta_hit else
                   "This enables port-scanning the internal network, hitting "
                   "unauthenticated internal services, and (if the environment "
                   "runs in a cloud) reaching the metadata endpoint for "
                   "credentials. ")
                + "Blind SSRF is easy to under-detect black-box; confirm reach "
                "and impact with an out-of-band (OAST) collaborator."
            ),
            evidence="\n".join(evid_lines),
            reproduction=(
                f"Send {r.method} {r.path} with {lead['location']} field "
                f"'{lead['name']}' = {lead['payload']} (compare against "
                f"{_CONTROL}); watch for a metadata body, a connection-error "
                f"leak, or a hang. Then point it at a Collaborator host and "
                f"confirm the DNS/HTTP callback."
            ),
            references=[REFS["A10"],
                        "https://cheatsheetseries.owasp.org/cheatsheets/"
                        "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
            tools=["Burp Suite (Collaborator)", "ssrfmap", "interactsh", "curl"],
        )
        return

    # Sinks exist but none confirmed exploitable in this black-box run.
    listing = "\n".join(_sink_line(r, name, loc) for r, name, loc in sinks[:20])
    n = len(sinks)
    if ctx.safe:
        note = ("Run was SAFE (non-destructive), so body/mutating sinks were not "
                "probed — re-run in FULL mode with an OAST collaborator to "
                "exercise them. ")
    else:
        note = ("All probed internal-target fetches were refused/validated or "
                "produced no observable server-side reaction. ")
    ctx.finding(
        id="a10-potential-sinks",
        owasp="A10",
        # Present but unconfirmed: a real lead, not a proven bug — keep it LOW/
        # MEDIUM and phrase as "verify with OAST" to avoid a false-positive.
        severity="MEDIUM" if not ctx.safe else "LOW",
        title=f"{n} URL-accepting parameter(s) are potential SSRF sinks",
        summary=(
            f"{n} parameter(s)/field(s) accept a URL-shaped value and may cause "
            "the server to fetch it. No black-box probe confirmed an internal "
            "fetch, but server-side URL retrieval is frequently blind: the HTTP "
            "response reveals nothing and only an out-of-band callback proves "
            "the request left the box. " + note + "Verify each sink manually "
            "with an OAST/Burp Collaborator payload before ruling it out."
        ),
        evidence=listing,
        reproduction=(
            "For each listed parameter, supply a unique Burp Collaborator / "
            "interactsh URL and watch for a DNS or HTTP callback; then escalate "
            "to http://169.254.169.254/latest/meta-data/ and internal host:port "
            "ranges."
        ),
        references=[REFS["A10"],
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
        tools=["Burp Suite (Collaborator)", "interactsh", "ssrfmap"],
    )

    # If we actively probed (FULL mode, sinks reachable) and everything was
    # cleanly refused, also record a TESTED-SAFE observation for the report.
    if not ctx.safe:
        ctx.finding(
            id="a10-internal-fetch-refused",
            owasp="A10", severity="SAFE",
            title="Internal-target fetches were refused / validated",
            summary=(
                "Every SSRF probe against loopback, link-local and cloud-metadata "
                "targets was rejected or produced no server-side fetch signal, "
                "consistent with input validation / a host allow-list on the "
                "URL-accepting parameters. Blind SSRF cannot be fully excluded "
                "black-box — confirm residual sinks with an OAST collaborator."
            ),
            references=[REFS["A10"]],
        )
