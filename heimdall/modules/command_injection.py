"""A03 — OS command injection (time-based blind).

Command injection is the highest-impact injection class (direct RCE) and the
one black-box scanners most often miss, because a successful injection frequently
produces **no change in the response body** — the output is swallowed. The robust,
target-agnostic oracle is *time*: inject a shell command that sleeps for N seconds
and see whether the response is delayed by ~N. A timing oracle is self-verifying,
so unlike content-based guessing it barely false-positives — we still confirm every
hit by proving the delay *scales* with the number we inject (sleep 2 ≈ 2s, sleep 5
≈ 5s), which rules out a coincidentally-slow endpoint.

  1. Candidate discovery: every query param + string body field on the route map.
     Command sinks hide behind innocuous names (filename, host, format, name), so
     we don't restrict by name — the timing oracle keeps precision high regardless.
  2. Probing: baseline the endpoint's latency with a benign value, then fire a
     tight set of shell break-out payloads (``;`` ``|`` ``&`` ``$()`` `` `` `` ``
     newline; POSIX + Windows) carrying a sleep. A response that suddenly takes
     ~N seconds when baseline was fast is a hit.
  3. Confirmation: re-inject with a *different* delay and require the elapsed time
     to track it. Only a scaling delay is reported — as CRITICAL, since it is RCE.

Payloads only ever run ``sleep`` / ``ping`` (benign, non-destructive), but this
still executes attacker-chosen shell on the target, so body/mutating probes are
gated to FULL mode.
"""

from __future__ import annotations

import requests

from ..core.context import Context
from ..core.reqbuild import build_request, string_body_fields
from ..core.taxonomy import REFS
from ..discovery.openapi import body_field_names
from .base import module

_BENIGN = "heimdall"

# Two delays: a hit must reproduce with the elapsed time tracking the injected
# value, so a coincidentally-slow endpoint (constant latency) can't confirm.
_LONG = 5
_SHORT = 2

# Shell break-out shapes, POSIX + Windows. ``{d}`` is the sleep seconds. We keep
# the set tight (high-signal) so a non-vulnerable param costs ~one baseline of
# fast requests, not a stall per payload. Each also has a "prefix a valid value"
# variant so a field that's used mid-command (not just concatenated raw) still
# breaks out.
def _payloads(d: int) -> list[str]:
    return [
        f"; sleep {d}",
        f"| sleep {d}",
        f"& sleep {d}",
        f"&& sleep {d}",
        f"|| sleep {d}",
        f"`sleep {d}`",
        f"$(sleep {d})",
        f"\n sleep {d}",
        f"{_BENIGN}; sleep {d}",
        f"{_BENIGN} & ping -n {d + 1} 127.0.0.1",  # Windows: ping N ≈ N-1 s
        f"{_BENIGN} | ping -c {d} 127.0.0.1",       # POSIX ping fallback
    ]


_MAX_CANDIDATES = 24
# Per-probe ceiling: comfortably above _LONG so an injected sleep completes, but
# bounded so a genuinely hung endpoint doesn't wedge the run.
_TIMEOUT = _LONG + 6

# A hit: the long-delay probe took at least this long while baseline was quick.
_HIT_FLOOR = _LONG - 0.7           # ~4.3s for a 5s sleep
_BASELINE_CEIL = 2.0               # baseline must be faster than this to trust
_SHORT_BAND = (_SHORT - 0.9, _SHORT + 1.8)   # confirm: short delay lands here


@module("cmdi", "OS Command Injection (time-based)", destructive=True)
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    candidates = _discover(ctx)
    if not candidates:
        ctx.note("command-injection: no query/body parameters to probe")
        return

    confirmed: list[dict] = []
    probed = 0
    for route, name, location in candidates[:_MAX_CANDIDATES]:
        if location == "body" and ctx.safe:
            continue
        if location == "query" and route.method != "GET" and ctx.safe:
            continue
        probed += 1
        hit = _probe_param(ctx, route, name, location, token)
        if hit:
            confirmed.append(hit)

    ctx.note(f"command-injection: probed {probed} parameter(s), "
             f"{len(confirmed)} confirmed via scaling time delay")
    if confirmed:
        _report_confirmed(ctx, confirmed)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery ────────────────────────────────────────────────────────────────

def _discover(ctx: Context) -> list[tuple]:
    out: list[tuple] = []
    seen: set[tuple[str, str, str]] = set()
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
    # Prefer shell-hinty names first so the candidate cap keeps the likeliest
    # sinks (timing still validates whatever we reach).
    out.sort(key=lambda t: 0 if _shell_hint(t[1]) else 1)
    return out


_SHELL_HINTS = ("cmd", "command", "exec", "host", "ip", "domain", "ping", "dns",
                "file", "filename", "path", "name", "url", "format", "ext",
                "target", "addr", "shell", "run", "script", "archive", "output")


def _shell_hint(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _SHELL_HINTS)


# ── probing ──────────────────────────────────────────────────────────────────

def _elapsed(resp) -> float:
    try:
        return resp.elapsed.total_seconds()
    except Exception:  # pragma: no cover - defensive
        return 0.0


def _send(ctx: Context, route, name: str, location: str, value: str,
          token: str | None):
    """Fire one probe; return (elapsed_seconds, ok) or (timeout, False)."""
    try:
        if location == "query":
            path = route.fill_path({p: "1" for p in route.path_params})
            resp = ctx.get(path, params={name: value}, token=token,
                           timeout=_TIMEOUT, retry_429=False)
        else:
            overrides = {name: value}
            path, body = build_request(ctx, route, token, overrides=overrides)
            resp = ctx.request(route.method, path, token=token, json=body,
                               timeout=_TIMEOUT, retry_429=False)
        return _elapsed(resp), True
    except requests.Timeout:
        # A hang past _TIMEOUT is itself a strong delay signal (sleep may exceed
        # our ceiling under load) — treat it as a max-length elapsed.
        return float(_TIMEOUT), True
    except requests.RequestException:
        return 0.0, False


def _probe_param(ctx: Context, route, name: str, location: str,
                 token: str | None) -> dict | None:
    # Baseline twice, keep the faster — smooths a cold first request so a slow
    # warm-up doesn't look like an injection later.
    b1, ok1 = _send(ctx, route, name, location, _BENIGN, token)
    b2, ok2 = _send(ctx, route, name, location, _BENIGN, token)
    if not (ok1 or ok2):
        return None
    baseline = min(b1, b2)
    if baseline >= _BASELINE_CEIL:
        return None  # endpoint is slow anyway — timing oracle unreliable here

    for payload in _payloads(_LONG):
        elapsed, ok = _send(ctx, route, name, location, payload, token)
        if not ok:
            continue
        if elapsed >= _HIT_FLOOR and elapsed - baseline >= _HIT_FLOOR - _BASELINE_CEIL:
            # Confirm the delay SCALES: same break-out with the short delay must
            # land in the short band, and re-running the long delay must stay long.
            short_payload = payload.replace(f"sleep {_LONG}", f"sleep {_SHORT}") \
                                   .replace(f"-n {_LONG + 1}", f"-n {_SHORT + 1}") \
                                   .replace(f"-c {_LONG}", f"-c {_SHORT}")
            short_el, sok = _send(ctx, route, name, location, short_payload, token)
            long_el, lok = _send(ctx, route, name, location, payload, token)
            scales = (sok and lok
                      and _SHORT_BAND[0] <= short_el <= _SHORT_BAND[1]
                      and long_el >= _HIT_FLOOR
                      and long_el - short_el >= 1.5)
            if scales:
                return {
                    "route": route, "name": name, "location": location,
                    "payload": payload, "baseline": baseline,
                    "short": short_el, "long": long_el,
                }
    return None


# ── findings ─────────────────────────────────────────────────────────────────

def _report_confirmed(ctx: Context, confirmed: list[dict]) -> None:
    lead = confirmed[0]
    r = lead["route"]
    lines = []
    for c in confirmed[:15]:
        cr = c["route"]
        lines.append(
            f"  {cr.method} {cr.path} [{c['location']}:{c['name']}] "
            f"payload={c['payload']!r}\n"
            f"      baseline={c['baseline']:.2f}s  sleep2={c['short']:.2f}s  "
            f"sleep5={c['long']:.2f}s  (delay tracks the injected value)"
        )
    ctx.finding(
        id="a03-command-injection",
        owasp="A03", severity="CRITICAL",
        title=(f"OS command injection via {lead['name']} on {r.method} {r.path}"
               + (f" (+{len(confirmed) - 1} more)" if len(confirmed) > 1 else "")),
        summary=(
            "A caller-controlled parameter is concatenated into a shell command "
            "on the server. Injecting a `sleep` through shell metacharacters "
            "(`;` `|` `&` `$()` backticks / newline) delayed the response by the "
            "exact number of seconds injected — proven by re-running with a "
            "different delay and watching the response time track it. This is "
            "remote code execution: an attacker can run arbitrary commands as the "
            "app's OS user, read/modify files, pivot into the network, and exfil "
            "credentials. Blind (no output echoed) does not reduce the impact."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=(f"{r.method} {r.path}  ({lead['location']} '{lead['name']}' = "
                 f"{lead['payload']!r})"),
        reproduction=(
            f"Send {r.method} {r.path} with {lead['location']} field "
            f"'{lead['name']}' = '{_BENIGN}; sleep 5' and time the response "
            f"(~5s); repeat with 'sleep 2' (~2s) to confirm the delay scales. "
            f"Then swap in an out-of-band payload (nslookup/curl to a "
            f"Collaborator host) to prove code execution and exfiltrate output."
        ),
        references=[REFS["A03"],
                    "https://portswigger.net/web-security/os-command-injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "OS_Command_Injection_Defense_Cheat_Sheet.html"],
        tools=["Burp Suite (Collaborator)", "commix", "interactsh"],
    )


def _report_safe(ctx: Context, probed: int) -> None:
    ctx.finding(
        id="a03-command-injection-safe",
        owasp="A03", severity="SAFE",
        title="No time-based OS command injection observed",
        summary=(
            f"Injected shell break-out payloads carrying a timed `sleep` into "
            f"{probed} parameter(s)/field(s); none produced a scaling response "
            "delay, consistent with no parameter reaching a shell (or reaching "
            "one only via a safe, non-shell API). Blind command injection through "
            "a channel with no timing signal cannot be fully excluded black-box — "
            "confirm any residual shell-touching sink with an OAST payload."
        ),
        references=[REFS["A03"],
                    "https://portswigger.net/web-security/os-command-injection"],
    )
