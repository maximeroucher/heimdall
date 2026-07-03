"""A05 — HTTP Host header attacks.

Many apps build absolute URLs (password-reset links, email links, redirects)
from the incoming ``Host`` / ``X-Forwarded-Host`` header without validating it.
For a FastAPI backend the impactful abuse is:

  * **Password-reset / email-link poisoning** — trigger a victim's reset so the
    emailed link points at ``attacker.tld``; when the victim clicks, the token
    leaks to the attacker (account takeover) — PortSwigger's canonical
    Host-header lab, and the primary risk here.
  * **Routing-based SSRF** — a reverse proxy that forwards by Host can be steered
    at internal hosts.

Web cache poisoning is deliberately *not* claimed as a core impact: FastAPI has
no built-in HTTP cache, so it only applies if a CDN / reverse-proxy cache is
deployed in front — a deployment-specific condition we can't see black-box, and
so is mentioned only as a conditional.

Black-box, the reliable tell is **reflection**: send a unique canary host and
see whether it comes back in an absolute URL (the ``Location`` header, a response
header, or a link in the body) where it wasn't with the real Host. We test the
most abused vector (``X-Forwarded-Host``) and a raw ``Host`` override, and — most
importantly — the password-reset / forgot-password endpoint, since that's where
reflection turns into account takeover. A target that rejects a bogus Host
(400/421) or never reflects it is recorded TESTED-SAFE.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request
from ..core.taxonomy import REFS
from .base import module

# A canary that will never occur naturally in a well-formed response.
_CANARY = "evil-heimdall-hhi.test"
_MAX_TARGETS = 12


@module("host-header", "HTTP Host Header Attacks")
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    targets = _select_targets(ctx)
    if not targets:
        ctx.note("host-header: no reachable target endpoints")
        return

    reflections: list[dict] = []
    rejected = 0
    probed = 0
    for route in targets[:_MAX_TARGETS]:
        probed += 1
        outcome = _probe(ctx, route, token)
        if outcome == "rejected":
            rejected += 1
        elif isinstance(outcome, dict):
            reflections.append(outcome)

    ctx.note(f"host-header: probed {probed} endpoint(s); "
             f"{len(reflections)} reflected a poisoned host, {rejected} rejected it")
    if reflections:
        _report_reflection(ctx, reflections)
    elif probed:
        _report_safe(ctx, probed, rejected)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── target selection (structural, no name inspection) ────────────────────────

def _select_targets(ctx: Context) -> list:
    """A broad structural sample — GETs plus a capped set of write endpoints. We
    never pick endpoints by name (no 'reset'/'password' guessing); whether a
    poisoned Host is reflected is the only thing that matters, and that's
    behavioural."""
    gets = [r for r in ctx.routes if r.method == "GET" and not r.has_path_param]
    writes = [r for r in ctx.routes if r.method in ("POST", "PUT", "PATCH")]
    return gets + writes[:12]


# ── probing ──────────────────────────────────────────────────────────────────

def _poison_headers() -> list[dict]:
    return [
        {"X-Forwarded-Host": _CANARY},
        {"X-Forwarded-Host": _CANARY, "X-Forwarded-Proto": "https"},
        {"Host": _CANARY},
        {"Forwarded": f"host={_CANARY}"},
    ]


def _fire(ctx: Context, route, token, headers):
    path = route.fill_path({p: "1" for p in route.path_params})
    try:
        if route.method == "GET":
            return ctx.get(path, token=token, headers=headers,
                           timeout=10, retry_429=False, allow_redirects=False)
        _, body = build_request(ctx, route, token)
        return ctx.request(route.method, path, token=token, json=body,
                           headers=headers, timeout=10, retry_429=False,
                           allow_redirects=False)
    except requests.RequestException:
        return None


def _canary_in(resp) -> str | None:
    """Return where the canary host was reflected, or None."""
    if resp is None:
        return None
    loc = resp.headers.get("Location", "")
    if _CANARY in loc:
        return f"Location: {loc[:200]}"
    for h, v in resp.headers.items():
        if _CANARY in str(v):
            return f"header {h}: {str(v)[:160]}"
    try:
        if _CANARY in (resp.text or ""):
            i = resp.text.find(_CANARY)
            return f"body: …{resp.text[max(0, i - 40):i + 40]}…"
    except Exception:  # pragma: no cover - defensive
        pass
    return None


def _probe(ctx: Context, route, token):
    """Return a reflection record dict, "rejected", or None."""
    baseline = _fire(ctx, route, token, {})
    # If the canary somehow already appears with a clean Host, it's not our doing.
    base_has = _canary_in(baseline) is not None

    any_rejected = False
    for headers in _poison_headers():
        resp = _fire(ctx, route, token, headers)
        if resp is None:
            continue
        # A server that validates Host answers 400/421 to a bogus one — good.
        if resp.status_code in (400, 421):
            any_rejected = True
            continue
        where = _canary_in(resp)
        if where and not base_has:
            return {
                "route": route,
                "vector": next(iter(headers)), "headers": headers,
                "where": where, "status": resp.status_code,
            }
    return "rejected" if any_rejected else None


# ── findings ─────────────────────────────────────────────────────────────────

def _report_reflection(ctx: Context, refl: list[dict]) -> None:
    lead = refl[0]
    r = lead["route"]
    lines = [f"  {c['route'].method} {c['route'].path}\n"
             f"      via {c['vector']}: {_CANARY} -> reflected in {c['where']}"
             for c in refl[:15]]
    ctx.finding(
        id="a05-host-header-reflection",
        owasp="A05", severity="MEDIUM",
        title=(f"Client-controlled Host reflected on {r.method} {r.path}"
               + (f" (+{len(refl) - 1} more)" if len(refl) > 1 else "")),
        summary=(
            "The application echoes a caller-supplied Host / X-Forwarded-Host "
            "header back into an absolute URL without validating it against an "
            "allow-list. Wherever the app turns that URL into an emailed or "
            "absolute link — a password-reset / verification link is the classic "
            "case — an attacker can point it at their own host: request a reset "
            "for a victim with a poisoned Host and the emailed link (and its "
            "token) goes to the attacker, i.e. account takeover. (Web-cache "
            "poisoning would additionally require a CDN/reverse-proxy cache in "
            "front — FastAPI has none itself — so that angle is "
            "deployment-conditional, not assumed.) Validate Host/X-Forwarded-Host "
            "against an explicit allow-list (FastAPI's TrustedHostMiddleware) and "
            "build outbound URLs from server-side configuration, not request "
            "headers."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=(f"{r.method} {r.path}  with {lead['vector']}: {_CANARY}"),
        reproduction=(
            f"Send {r.method} {r.path} with header '{lead['vector']}: {_CANARY}' "
            f"and observe {_CANARY} reflected in {lead['where']}. Trace where this "
            "value becomes an emailed/absolute link (esp. a reset/verification "
            "flow) and confirm the link host is attacker-controlled."
        ),
        references=[REFS["A05"],
                    "https://portswigger.net/web-security/host-header",
                    "https://portswigger.net/web-security/host-header/"
                    "exploiting/password-reset-poisoning"],
        tools=["Burp Suite", "Param Miner", "curl"],
    )


def _report_safe(ctx: Context, probed: int, rejected: int) -> None:
    ctx.finding(
        id="a05-host-header-safe",
        owasp="A05", severity="SAFE",
        title="Host / X-Forwarded-Host not reflected",
        summary=(
            f"Sent a canary host via Host, X-Forwarded-Host and Forwarded across "
            f"{probed} endpoint(s); none reflected it into a Location header, "
            "response header or body link"
            + (f", and {rejected} rejected the bogus Host outright (400/421)"
               if rejected else "")
            + ". No black-box Host-header poisoning surface was found. Confirm the "
            "password-reset email itself builds links from server config (not the "
            "request Host) if you can observe the mail."
        ),
        references=[REFS["A05"],
                    "https://portswigger.net/web-security/host-header"],
    )
