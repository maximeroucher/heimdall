"""A04 — Race conditions / TOCTOU on once-or-limited operations.

Check-then-act guards (claim a code once, redeem a coupon, cast one vote, debit a
balance) break under concurrency: many requests pass the check before any commits
the effect. Heimdall fires a burst of *simultaneous* identical requests (aligned
on a barrier) at candidate endpoints, then probes sequentially:

  * >1 of the concurrent burst succeeds, AND
  * a later sequential repeat is rejected (the resource is now consumed),

means concurrency defeated a once-only guard — a race.

Candidate selection is purely BEHAVIOURAL — no verb/schema hint decides what to
test. Every reachable mutating endpoint is bursted; an endpoint is a limited/once
operation iff a sequential repeat is rejected afterwards (the resource was
consumed). Idempotent / unlimited endpoints simply fail that test and aren't
flagged. Naming is irrelevant, so it finds races the tester never thought to name.
Destructive (creates/consumes data), so FULL mode only, bounded by a budget.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from ..core.context import Context
from ..core.http import HttpClient
from ..core.reqbuild import build_request
from .base import module

_BURST = 20
_MAX_ENDPOINTS = 60   # cost/destructiveness budget (bursts are ~23 requests each)


@module("race", "Race conditions / TOCTOU", destructive=True)
def run(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("safe mode: skipping race-condition probes (destructive)")
        return
    princ = ctx.principal("attacker", "user") or ctx.profile.any_authed()
    token = princ.token if princ and princ.authed else None
    # Purely behaviour-driven: burst EVERY reachable mutating endpoint and let the
    # outcome classify it. No verb/schema hint decides what to test — an endpoint
    # is a race target iff (a) a burst reaches it and (b) a sequential repeat is
    # then rejected (proving a consumable/limited invariant). Naming is irrelevant.
    # DELETE is excluded: its "sequential repeat is rejected" signal is trivially
    # true (the resource is simply gone), which confounds the limited/once
    # classifier — duplicate concurrent success on a DELETE removes one row and
    # returns success N times, with no double-spend/over-grant to exploit. Real
    # TOCTOU races duplicate a VALUE (redeem/withdraw/mint), which lives on
    # POST/PUT/PATCH.
    candidates = [r for r in ctx.routes
                  if r.method in ("POST", "PUT", "PATCH") and len(r.path_params) <= 1]
    if not candidates:
        ctx.note("no mutating endpoints to race")
        return
    if len(candidates) > _MAX_ENDPOINTS:
        ctx.note(f"{len(candidates)} mutating endpoints; racing the first {_MAX_ENDPOINTS} "
                 "(budget — raise _MAX_ENDPOINTS for full coverage)")
        candidates = candidates[:_MAX_ENDPOINTS]

    raced = []
    idempotent = []    # ≥2 concurrent successes but all returned IDENTICAL responses
    limited = 0        # endpoints whose sequential-repeat proved a once/limited invariant
    reachable = 0
    for r in candidates:
        # Build a VALID request (real path/FK ids from related endpoints + typed
        # body) so the burst reaches the handler instead of 404/422-ing, then let
        # the OUTCOME classify — no lexical/schema assumption about the endpoint.
        path, body = build_request(ctx, r, token, principal=princ)
        result = _probe(ctx, r.method, path, token, body)
        if result is None:
            continue                       # never succeeded -> unreachable / gated
        reachable += 1
        conc_ok, seq_ok, distinct = result
        # The invariant is "limited/once" iff the resource is now consumed: a
        # sequential repeat is rejected. Idempotent / unlimited ops (seq still
        # succeeds) simply aren't race targets. This is the whole classifier.
        if seq_ok > 0:
            continue
        limited += 1
        if conc_ok < 2:
            continue
        # ≥2 concurrent successes. But "2xx count" alone over-reports: an
        # idempotent toggle (favorite / like / follow, or any INSERT ... ON
        # CONFLICT DO NOTHING) lets N concurrent requests all return 2xx while the
        # persisted invariant stays at ONE application — no double-spend. Those
        # duplicate successes read the same pre-state and return BYTE-IDENTICAL
        # responses. A genuine cumulative race (distinct rows created, a balance
        # debited N times, a counter advanced) instead yields DIVERGENT responses.
        # So require response divergence to confirm real over-application.
        if distinct >= 2:
            raced.append((r, conc_ok))
        else:
            idempotent.append((r, conc_ok))

    if idempotent:
        ctx.note("race: "
                 + "; ".join(f"{r.method} {r.path} ({n}/{_BURST} concurrent 2xx but "
                             "identical responses)" for r, n in idempotent[:8])
                 + " — duplicate successes returned identical responses, consistent with an "
                 "idempotent no-op (favorite/like/follow, INSERT..ON CONFLICT) rather than a "
                 "cumulative race; not flagged. Verify the persisted invariant if any is a "
                 "hidden accumulator.")

    if raced:
        sample = "\n".join(f"  {r.method} {r.path}: {n}/{_BURST} concurrent succeeded with "
                           f"DIVERGING responses, then sequential repeats rejected"
                           for r, n in raced[:15])
        ctx.finding(
            id="a04-race-toctou", owasp="A04", severity="HIGH",
            title=f"Race condition (TOCTOU) on {len(raced)} limited operation(s)",
            summary=(
                "These endpoints enforce a limited/once invariant (a sequential repeat is "
                "rejected) but a burst of simultaneous identical requests succeeded MORE THAN "
                "ONCE AND the successes returned DIVERGING responses — the check-then-act guard "
                "isn't atomic and the duplicate successes reflect distinct cumulative effects "
                "(not idempotent no-ops). Depending on the endpoint this enables double-spend, "
                "multiple redemptions of a one-time code, quota/limit bypass, or duplicate "
                "votes. Use atomic DB operations / row locks / unique constraints, not "
                "read-then-write."
            ),
            evidence=sample,
            route=f"{raced[0][0].method} {raced[0][0].path}",
            request=f"{_BURST}x concurrent  {raced[0][0].method} {raced[0][0].path}  "
                    "(barrier-aligned burst)",
            reproduction=f"Send ~{_BURST} concurrent identical {raced[0][0].method} "
                         f"{raced[0][0].path} requests (Burp Turbo Intruder / single-packet).",
            references=["https://owasp.org/Top10/A04_2021-Insecure_Design/",
                        "https://portswigger.net/web-security/race-conditions"],
            tools=["Burp Turbo Intruder", "ffuf -rate", "custom asyncio script"],
        )
    elif limited:
        ctx.finding(
            id="a04-race-toctou", owasp="A04", severity="SAFE",
            title="Limited operations resist concurrent duplication",
            summary=f"Of {reachable} reachable mutating endpoint(s), {limited} enforced a "
                    "once/limited invariant (sequential repeat rejected); a concurrent burst "
                    "of each either yielded a single success or only idempotent duplicate "
                    "successes (identical responses) — the guards look atomic.",
        )
    else:
        ctx.note(f"raced {reachable} reachable mutating endpoint(s); none exposed a "
                 "limited invariant to break (or preconditions blocked deeper ones)")


def _probe(ctx: Context, method: str, path: str, token: str | None, body: dict):
    """Return (concurrent_successes, sequential_successes_after, distinct_bodies)
    or None to skip.

    ``distinct_bodies`` is the number of DISTINCT response bodies among the
    concurrent successes — 1 means every duplicate success returned the same
    thing (idempotent no-op), ≥2 means the successes reflect diverging state (a
    real cumulative race). Skips endpoints where even a single call doesn't
    clearly succeed (a body we couldn't synthesise validly), so we don't misread
    validation errors as races.
    """
    base = ctx.base_url
    kind = ctx.auth.auth_kind
    name = ctx.auth.credential_name

    def fire() -> tuple[int, str]:
        cli = HttpClient(base, scheme=ctx.auth.header_scheme, auth_kind=kind,
                         credential_name=name, timeout=15)
        try:
            r = cli.req(method, path, token=token, json=body, retry_429=False)
            return r.status_code, (r.text or "")
        except Exception:  # noqa: BLE001
            return 0, ""

    # Barrier-aligned concurrent burst.
    barrier = threading.Barrier(_BURST)

    def worker(_):
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        return fire()

    try:
        with ThreadPoolExecutor(max_workers=_BURST) as ex:
            results = list(ex.map(worker, range(_BURST)))
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"race burst on {method} {path} failed: {exc}")
        return None
    ok_bodies = [b for s, b in results if 200 <= s < 300]
    conc_ok = len(ok_bodies)
    if conc_ok == 0:
        return None  # never succeeded (needs a real body / not reachable) — skip
    distinct = len({b.strip() for b in ok_bodies})
    # Sequential repeats: is the operation now consumed / rejected?
    seq_ok = 0
    for _ in range(3):
        if 200 <= fire()[0] < 300:
            seq_ok += 1
    return conc_ok, seq_ok, distinct
