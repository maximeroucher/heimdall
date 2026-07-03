"""A04 — Race conditions / TOCTOU on once-or-limited operations.

Check-then-act guards (claim a code once, redeem a coupon, cast one vote, debit a
balance) break under concurrency: many requests pass the check before any commits
the effect. Heimdall fires a burst of *simultaneous* identical requests (aligned
on a barrier) at candidate endpoints, then probes sequentially:

  * >1 of the concurrent burst succeeds, AND
  * a later sequential repeat is rejected (the resource is now consumed),

means concurrency defeated a once-only guard — a race. Destructive, so FULL mode
only; scoped to endpoints whose name implies a limited/one-shot action.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from ..core.context import Context
from ..core.http import HttpClient
from .base import looks_like_id_param, module

_ONCE_HINTS = (
    "claim", "redeem", "redemption", "coupon", "voucher", "promo", "apply",
    "vote", "purchase", "buy", "order", "checkout", "book", "reserve", "register",
    "use", "consume", "withdraw", "transfer", "cashout", "payout", "refund",
    "like", "follow", "join", "enroll", "submit", "confirm", "activate", "accept",
    "spend", "debit", "topup", "recharge", "enter", "signup",
)
_BURST = 20


def _is_once_op(route) -> bool:
    blob = f"{route.path} {route.operation_id}".lower()
    return any(h in blob for h in _ONCE_HINTS)


@module("race", "Race conditions / TOCTOU", destructive=True)
def run(ctx: Context) -> None:
    if ctx.safe:
        ctx.note("safe mode: skipping race-condition probes (destructive)")
        return
    princ = ctx.principal("attacker", "user") or ctx.profile.any_authed()
    token = princ.token if princ and princ.authed else None
    candidates = [
        r for r in ctx.routes
        if r.method in ("POST", "PUT", "PATCH", "DELETE")
        and len(r.path_params) <= 1 and _is_once_op(r)
    ]
    if not candidates:
        ctx.note("no once/limited-operation endpoints matched; race probes skipped")
        return

    raced = []
    tested = 0
    for r in candidates[:25]:
        val = None
        if r.path_params:
            pname = r.path_params[0]
            val = (princ.user_id if princ and looks_like_id_param(pname) and "user" in pname.lower()
                   else "heimdall-race-1")
        path = r.fill_path({r.path_params[0]: val}) if r.path_params else r.path
        result = _probe(ctx, r.method, path, token)
        if result is None:
            continue
        tested += 1
        conc_ok, seq_ok = result
        if conc_ok >= 2 and seq_ok == 0:
            raced.append((r, conc_ok))

    if raced:
        sample = "\n".join(f"  {r.method} {r.path}: {n}/{_BURST} concurrent succeeded, "
                           f"then sequential repeats rejected" for r, n in raced[:15])
        ctx.finding(
            id="a04-race-toctou", owasp="A04", severity="HIGH",
            title=f"Race condition (TOCTOU) on {len(raced)} once/limited operation(s)",
            summary=(
                "A burst of simultaneous identical requests succeeded MORE THAN ONCE on an "
                "operation that is rejected on a sequential repeat — the check-then-act guard "
                "isn't atomic. Depending on the endpoint this enables double-spend, multiple "
                "redemptions of a one-time code, quota/limit bypass, or duplicate votes. Use "
                "atomic DB operations / row locks / unique constraints, not read-then-write."
            ),
            evidence=sample,
            reproduction=f"Send ~{_BURST} concurrent identical {raced[0][0].method} "
                         f"{raced[0][0].path} requests (Burp Turbo Intruder / single-packet).",
            references=["https://owasp.org/Top10/A04_2021-Insecure_Design/",
                        "https://portswigger.net/web-security/race-conditions"],
            tools=["Burp Turbo Intruder", "ffuf -rate", "custom asyncio script"],
        )
    elif tested:
        ctx.finding(
            id="a04-race-toctou", owasp="A04", severity="SAFE",
            title="Once/limited operations resist concurrent duplication",
            summary=f"Fired {_BURST} concurrent requests at {tested} one-shot-looking "
                    "endpoint(s); none allowed more than a single success — guards look atomic.",
        )


def _probe(ctx: Context, method: str, path: str, token: str | None):
    """Return (concurrent_successes, sequential_successes_after) or None to skip.

    Skips endpoints where even a single call doesn't clearly succeed (they need a
    body we can't synthesise), so we don't misread validation errors as races.
    """
    base = ctx.base_url
    kind = ctx.auth.auth_kind
    name = ctx.auth.credential_name

    def fire() -> int:
        cli = HttpClient(base, scheme=ctx.auth.header_scheme, auth_kind=kind,
                         credential_name=name, timeout=15)
        try:
            return cli.req(method, path, token=token, json={}, retry_429=False).status_code
        except Exception:  # noqa: BLE001
            return 0

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
            statuses = list(ex.map(worker, range(_BURST)))
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"race burst on {method} {path} failed: {exc}")
        return None
    conc_ok = sum(1 for s in statuses if 200 <= s < 300)
    if conc_ok == 0:
        return None  # never succeeded (needs a real body / not reachable) — skip
    # Sequential repeats: is the operation now consumed / rejected?
    seq_ok = 0
    for _ in range(3):
        if 200 <= fire() < 300:
            seq_ok += 1
    return conc_ok, seq_ok
