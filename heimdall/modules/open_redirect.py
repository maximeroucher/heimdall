"""A01 — Open redirect.

A parameter that steers where the server sends the browser next (``next``,
``redirect_uri``, ``return_to``, ``callback``, …). If the app 3xx-redirects (or
emits a client-side redirect) to an attacker-supplied *external* host without
checking it against an allow-list, it's an open redirect: useful for phishing
(a link on the trusted domain that bounces to the attacker) and — when the sink
is an OAuth ``redirect_uri`` — for stealing the authorization ``code`` and taking
over accounts.

Detection is direct and low-false-positive: send a unique attacker-canary URL
through the parameter and check whether the ``Location`` header (or a body-level
meta-refresh / ``window.location``) points at the *canary host*. Because we look
for our own canary host specifically — not merely that our value was echoed — a
param that just reflects text without redirecting won't trip it. We also try the
classic filter bypasses (scheme-relative ``//host``, ``https:host``, and a
``trusted.tld.attacker`` suffix trick).
"""

from __future__ import annotations

import re

import requests

from ..core.context import Context
from ..core.reqbuild import build_request
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

_CANARY_HOST = "evil-heimdall-redir.test"
# Payload → the host we expect to see if the redirect is open. The suffix-trick
# (trusted.tld.attacker) checks naive startswith()/substring allow-list checks.
_PAYLOADS = [
    (f"https://{_CANARY_HOST}/", _CANARY_HOST),
    (f"//{_CANARY_HOST}/", _CANARY_HOST),
    (f"https:{_CANARY_HOST}", _CANARY_HOST),
    (f"https://trusted.example.{_CANARY_HOST}/", _CANARY_HOST),
    (f"/\\{_CANARY_HOST}/", _CANARY_HOST),
]

# No parameter-name list: we don't guess which param "looks like" a redirect.
# Every reachable param gets the canary URL, and the server actually issuing a
# redirect to the canary host is the only thing that flags it (behavioural).
_MAX_CANDIDATES = 80


@module("open-redirect", "Open Redirect")
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    candidates = _discover(ctx)
    if not candidates:
        ctx.note("open-redirect: no parameters in the API surface to probe")
        return

    confirmed: list[dict] = []
    probed = 0
    for route, name, location in candidates[:_MAX_CANDIDATES]:
        if location == "body" and ctx.safe:
            continue
        if location == "query" and route.method != "GET" and ctx.safe:
            continue
        probed += 1
        hit = _probe(ctx, route, name, location, token)
        if hit:
            confirmed.append(hit)

    ctx.note(f"open-redirect: probed {probed} param(s), "
             f"{len(confirmed)} redirected to the attacker canary host")
    if confirmed:
        _report_confirmed(ctx, confirmed)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery ────────────────────────────────────────────────────────────────

def _discover(ctx: Context) -> list[tuple]:
    """Every query param and string body field — no name filtering. The redirect
    behaviour, not the name, decides."""
    out: list[tuple] = []
    seen: set = set()
    for r in ctx.routes:
        for p in r.query_params:
            name = p.get("name") if isinstance(p, dict) else None
            if name and (r.key, name, "query") not in seen:
                seen.add((r.key, name, "query"))
                out.append((r, name, "query"))
        if r.method in ("POST", "PUT", "PATCH"):
            for name in body_field_names(r):
                if (r.key, name, "body") not in seen:
                    seen.add((r.key, name, "body"))
                    out.append((r, name, "body"))
    return out


# ── probing ──────────────────────────────────────────────────────────────────

def _redirects_to(resp, host: str) -> str | None:
    """Return the evidence string if this response redirects to ``host``."""
    if resp is None:
        return None
    loc = resp.headers.get("Location", "")
    if 300 <= resp.status_code < 400 and _nav_host_is(loc, host):
        return f"HTTP {resp.status_code} Location: {loc[:200]}"
    # Body-level redirect (meta refresh / JS) that navigates to the canary host.
    try:
        body = resp.text or ""
    except Exception:  # pragma: no cover - defensive
        body = ""
    low = body.lower()
    if host in low and ("http-equiv=\"refresh\"" in low or "window.location" in low
                        or "location.href" in low or "location.replace" in low):
        # Confirm a URL in the body actually *navigates* to the canary host
        # (not merely mentions it in a path/querystring of a same-origin URL).
        for cand in _URL_IN_BODY.findall(body):
            if _nav_host_is(cand, host):
                i = low.find(host)
                return f"client-side redirect in body: …{body[max(0, i - 50):i + 30]}…"
    return None


# URL-ish tokens in a body (absolute, scheme-relative, or opaque scheme:host).
_URL_IN_BODY = re.compile(r"""(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//[^\s"'<>()]+"""
                          r"""|https?:[^\s"'<>()/]+""")


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def _nav_host(url: str) -> str:
    """The host a browser actually navigates to for this Location value.

    Mirrors browser authority parsing so we match on the *effective* host, not a
    naive substring: backslashes normalise to slashes; a leading ``scheme:`` is
    stripped; ``//authority`` (or the opaque ``https:host`` form) yields a host;
    a path-relative or path-absolute value has no external host. Userinfo
    (``user@host``) and port are stripped so ``https://canary@real.host/`` reads
    as ``real.host`` (goes to real.host — NOT an open redirect to the canary),
    and ``/goto/https://canary/`` reads as the app's own host (canary is only in
    the path). This is what kills the classic open-redirect false positives."""
    u = url.strip().replace("\\", "/")
    m = _SCHEME_RE.match(u)
    had_scheme = bool(m)
    if m:
        u = u[m.end():]
    if u.startswith("//"):
        u = u[2:]
    elif u.startswith("/") or not had_scheme:
        return ""                    # path (relative/absolute) → same origin
    # else: opaque "scheme:host" form → the remainder starts with the host
    authority = u.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = authority.split("@")[-1].split(":", 1)[0]     # drop userinfo + port
    return host.lower()


def _nav_host_is(loc: str, canary: str) -> bool:
    """True if the browser would navigate to the canary host or a subdomain of
    it (a subdomain of the attacker-controlled canary domain is still theirs)."""
    h = _nav_host(loc)
    return bool(h) and (h == canary or h.endswith("." + canary))


def _probe(ctx: Context, route, name: str, location: str, token: str | None):
    for payload, host in _PAYLOADS:
        try:
            if location == "query":
                path = route.fill_path({p: "1" for p in route.path_params})
                resp = ctx.get(path, params={name: payload}, token=token,
                               timeout=10, retry_429=False, allow_redirects=False)
            else:
                _, body = build_request(ctx, route, token, overrides={name: payload})
                path = route.fill_path({p: "1" for p in route.path_params})
                resp = ctx.request(route.method, path, token=token, json=body,
                                   timeout=10, retry_429=False, allow_redirects=False)
        except requests.RequestException:
            continue
        where = _redirects_to(resp, host)
        if where:
            return {"route": route, "name": name, "location": location,
                    "payload": payload, "where": where}
    return None


# ── findings ─────────────────────────────────────────────────────────────────

def _report_confirmed(ctx: Context, confirmed: list[dict]) -> None:
    # An OAuth redirect_uri open redirect escalates to code/token theft.
    oauth = any(c["name"].lower().replace("-", "_") == "redirect_uri"
                for c in confirmed)
    lead = next((c for c in confirmed
                 if c["name"].lower().replace("-", "_") == "redirect_uri"),
                confirmed[0])
    r = lead["route"]
    lines = []
    for c in confirmed[:15]:
        cr = c["route"]
        lines.append(f"  {cr.method} {cr.path} [{c['location']}:{c['name']}] "
                     f"payload={c['payload']!r}\n      -> {c['where']}")
    severity = "HIGH" if oauth else "MEDIUM"
    ctx.finding(
        id="a01-open-redirect",
        owasp="A01", severity=severity,
        title=(f"Open redirect via {lead['name']} on {r.method} {r.path}"
               + (" (OAuth redirect_uri → code theft)" if oauth else "")
               + (f" (+{len(confirmed) - 1} more)" if len(confirmed) > 1 else "")),
        summary=(
            "A redirect parameter sends the browser to an attacker-supplied "
            "external host without validating it against an allow-list — the "
            "server issued a redirect to our canary host. "
            + ("Because the sink is an OAuth `redirect_uri`, an attacker can "
               "register a link that makes the provider deliver the victim's "
               "authorization `code` to the attacker's host — account takeover, "
               "not just phishing. "
               if oauth else
               "This lets an attacker craft a link on the trusted domain that "
               "silently bounces victims to a phishing/malware page, and can be "
               "chained to bypass SSRF/redirect-based allow-lists. ")
            + "Restrict redirect targets to a server-side allow-list of paths / "
            "registered origins; never redirect to a raw request-supplied URL."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=(f"{r.method} {r.path}  ({lead['location']} '{lead['name']}' = "
                 f"{lead['payload']})"),
        reproduction=(
            f"Send {r.method} {r.path} with {lead['location']} '{lead['name']}' = "
            f"{lead['payload']} and follow the response: it redirects to "
            f"{_CANARY_HOST} (an external host). "
            + ("For the OAuth flow, complete it with a victim and capture the "
               "code/token delivered to the attacker host." if oauth else
               "Host a lookalike page there to demonstrate the phishing impact.")
        ),
        references=[REFS["A01"],
                    "https://portswigger.net/web-security/oauth" if oauth
                    else "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
        tools=["Burp Suite", "curl -i"],
    )


def _report_safe(ctx: Context, probed: int) -> None:
    ctx.finding(
        id="a01-open-redirect-safe",
        owasp="A01", severity="SAFE",
        title="Redirect parameters validated (no open redirect)",
        summary=(
            f"Sent attacker-host canary URLs (absolute, scheme-relative, and "
            f"suffix-trick bypasses) through {probed} parameter(s); "
            "none produced a redirect to the attacker host, consistent with "
            "server-side allow-listing of redirect targets."
        ),
        references=[REFS["A01"],
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    )
