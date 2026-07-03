"""A07 — Identification and Authentication Failures.

Fully generic: every check reads the login/register shape off ``ctx.auth`` so it
works on any FastAPI target. Four probes, each self-skipping when it lacks what
it needs:
  1. Brute-force protection: hammer the login with a bogus password and look for
     a 429. If none appears, credential stuffing is unthrottled. If a 429 does
     appear, retry behind rotating ``X-Forwarded-For`` to catch a spoofable key.
  2. Account enumeration: compare the login response (status/body/coarse timing)
     for a known-existing vs. a definitely-nonexistent identity — plus the same
     probe against a forgot-password endpoint if one is exposed.
  3. Registration mass-assignment: register with privileged fields that are NOT
     in ``register_fields`` (role/is_admin/…), then log in and read ``me`` to see
     if any stuck — a self-service privilege escalation.
  4. Password policy: register with a trivially weak password and see if it takes.

Writes are gated behind ``ctx.safe`` (they create accounts on the target).
"""

from __future__ import annotations

import time

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

# Privileged fields we inject at registration but never declare in the form —
# if any of these is echoed back by the 'me' endpoint, mass-assignment is live.
_PRIV_FIELDS: dict = {
    "role": "admin",
    "is_admin": True,
    "is_superuser": True,
    "is_active": True,
    "is_verified": True,
    "account_type": "admin",
    "scopes": "API",
    "groups": ["admin"],
}
_ADMIN_TRUTHS = ("admin", "superuser", "super_admin", "administrator", "api")

# Module-level counter keeps re-run emails unique without random/time entropy.
_seq = [0]


def _next_suffix(ctx: Context) -> int:
    """A small, stable-ish but varied suffix so repeat runs don't collide."""
    _seq[0] += 1
    return len(ctx.profile.principals) * 100 + _seq[0]


def _login_attempt(ctx: Context, ident: str, pw: str, *, headers: dict | None = None):
    """Fire one login honoring ``ctx.auth.login_style``; returns the Response.

    ``retry_429=False``: this module must *observe* raw 429s to decide whether a
    rate limiter exists, so it opts out of the client's transparent back-off.
    """
    a = ctx.auth
    body = {a.username_field: ident, a.password_field: pw}
    if a.login_style in ("form", "oauth_password"):
        if a.login_style == "oauth_password":
            body["grant_type"] = "password"
        return ctx.post(a.login_path, data=body, headers=headers, retry_429=False)
    return ctx.post(a.login_path, json=body, headers=headers, retry_429=False)


@module("a07", "Authentication Failures")
def run(ctx: Context) -> None:
    if not ctx.auth.login_path:
        ctx.note("no login path discovered; A07 auth checks skipped")
        return
    _brute_force(ctx)
    _account_enum(ctx)
    _mass_assignment(ctx)
    _weak_password(ctx)


def _brute_force(ctx: Context) -> None:
    """~12 rapid bogus logins should trip a 429; if one does, test XFF bypass."""
    attacker = ctx.principal("attacker", "user")
    # Use the attacker's own email (or a throwaway) so we never lock out a real
    # user — a wrong password against our own account is harmless.
    ident = (attacker.email if attacker and attacker.email
             else f"heimdall.bruteforce+{_next_suffix(ctx)}@example.com")
    codes: list[int] = []
    tripped_at = None
    try:
        for i in range(12):
            resp = _login_attempt(ctx, ident, f"wrong-pw-{i}")
            codes.append(resp.status_code)
            if resp.status_code == 429 and tripped_at is None:
                tripped_at = i + 1
    except Exception as e:  # noqa: BLE001
        ctx.note(f"login brute-force probe errored: {e}")
        return

    if tripped_at is None:
        ctx.finding(
            id="a07-login-rate-limit",
            owasp="A07", severity="MEDIUM",
            title="No rate limiting on login — brute force / credential stuffing",
            summary=(
                "Twelve rapid login attempts with a bogus password all completed without a "
                "429 Too Many Requests. An attacker can run unlimited credential-stuffing or "
                "password-spray attempts; add per-account and per-IP throttling plus lockout "
                "or an exponential back-off."
            ),
            evidence=f"12 attempts for {ident!r} -> status codes {codes}",
            reproduction=f"for i in $(seq 12); do curl -s -o /dev/null -w '%{{http_code}} ' "
                         f"{ctx.base_url}{ctx.auth.login_path} -d '{ctx.auth.username_field}="
                         f"{ident}&{ctx.auth.password_field}=x$i'; done",
            references=[REFS["A07"], REFS["cheat-authz"]],
            tools=["hydra", "Burp (Intruder)", "patator"],
        )
        return

    # Rate limiting fired — good. Now see whether it is keyed on a spoofable
    # client-supplied header (X-Forwarded-For), which trivially defeats it.
    ctx.finding(
        id="a07-login-rate-limit",
        owasp="A07", severity="SAFE",
        title=f"Login is rate-limited (429 after {tripped_at} attempts)",
        summary=f"Repeated bogus logins for {ident!r} were throttled with HTTP 429 after "
                f"{tripped_at} attempts — brute-force protection is active.",
    )
    try:
        evaded = []
        for i in range(1, 21):
            xff = f"10.0.0.{i}"
            resp = _login_attempt(ctx, ident, f"xff-pw-{i}",
                                  headers={"X-Forwarded-For": xff})
            if resp.status_code != 429:
                evaded.append((xff, resp.status_code))
    except Exception as e:  # noqa: BLE001
        ctx.note(f"X-Forwarded-For bypass probe errored: {e}")
        return

    # If a healthy majority of spoofed-IP requests dodge the 429, the limiter is
    # trusting an attacker-controlled header.
    if len(evaded) >= 5:
        sample = ", ".join(f"{ip}->{code}" for ip, code in evaded[:8])
        ctx.finding(
            id="a07-rate-limit-xff-bypass",
            owasp="A07", severity="HIGH",
            title="Login rate limit keyed on spoofable X-Forwarded-For",
            summary=(
                "After the limiter engaged, rotating the X-Forwarded-For header let requests "
                "sail past the 429. Rate limiting bucketed on a client-supplied header can be "
                "reset at will by an attacker, nullifying brute-force protection. Key throttles "
                "on the real transport peer (or a trusted proxy hop count), not raw XFF."
            ),
            evidence=f"{len(evaded)}/20 spoofed-IP logins evaded the 429: {sample}",
            reproduction="Trigger the 429, then replay the same login while incrementing "
                         "the X-Forwarded-For header (10.0.0.1, 10.0.0.2, …).",
            references=[REFS["A07"], REFS["cheat-authz"]],
            tools=["Burp (Intruder + X-Forwarded-For)", "curl -H 'X-Forwarded-For: 10.0.0.1'"],
        )
    else:
        ctx.finding(
            id="a07-rate-limit-xff-bypass",
            owasp="A07", severity="SAFE",
            title="Login rate limit resists X-Forwarded-For spoofing",
            summary="Rotating the X-Forwarded-For header did not evade the 429; the limiter "
                    "is not keyed on that client-supplied header.",
        )


def _timed_login(ctx: Context, ident: str, pw: str) -> tuple[int, str, float]:
    """Return (status, body, avg seconds) over a couple of samples."""
    codes: list[int] = []
    body = ""
    durations: list[float] = []
    for _ in range(2):
        t0 = time.perf_counter()
        resp = _login_attempt(ctx, ident, pw)
        durations.append(time.perf_counter() - t0)
        codes.append(resp.status_code)
        body = resp.text[:400]
    avg = sum(durations) / len(durations)
    return codes[-1], body, avg


def _account_enum(ctx: Context) -> None:
    """Do existing vs. nonexistent identities look different at login?"""
    attacker = ctx.principal("attacker", "user")
    if not attacker or not attacker.email:
        ctx.note("no known-existing account available; enumeration check skipped")
        return
    known = attacker.email
    absent = f"heimdall.ghost+{_next_suffix(ctx)}@example.com"
    try:
        k_code, k_body, k_t = _timed_login(ctx, known, "definitely-wrong-pw")
        a_code, a_body, a_t = _timed_login(ctx, absent, "definitely-wrong-pw")
    except Exception as e:  # noqa: BLE001
        ctx.note(f"account-enumeration login probe errored: {e}")
        return

    # Heuristic signals: different status, a body that names the distinction, or
    # a coarse timing gap (>150 ms) hinting at a bcrypt-only-when-user-exists path.
    status_differs = k_code != a_code
    kb, ab = k_body.lower(), a_body.lower()
    body_differs = (("not found" in ab or "no such" in ab or "unknown" in ab or
                     "does not exist" in ab) and "not found" not in kb) or (kb != ab)
    timing_gap = abs(k_t - a_t) > 0.15

    if status_differs or (body_differs and (status_differs or timing_gap)):
        ctx.finding(
            id="a07-login-user-enum",
            owasp="A07", severity="LOW",
            title="Account enumeration via login response",
            summary=(
                "The login endpoint responds differently to an existing account vs. a "
                "nonexistent one (status, body, or timing), so an attacker can enumerate "
                "valid usernames before spraying passwords. Return an identical generic "
                "'invalid credentials' response and normalise timing. (Heuristic — confirm "
                "manually.)"
            ),
            evidence=f"known {known!r}    -> {k_code} ~{k_t*1000:.0f}ms  body={k_body[:120]!r}\n"
                     f"absent {absent!r} -> {a_code} ~{a_t*1000:.0f}ms  body={a_body[:120]!r}",
            reproduction=f"POST {ctx.auth.login_path} with a real vs. a made-up "
                         f"{ctx.auth.username_field} (wrong password both) and diff the responses.",
            references=[REFS["A07"], REFS["ps-massassign"]],
            tools=["Burp (Comparer)", "curl", "ffuf"],
        )
    else:
        ctx.finding(
            id="a07-login-user-enum",
            owasp="A07", severity="SAFE",
            title="Login response does not distinguish existing vs. unknown accounts",
            summary="Existing and nonexistent identities produced an indistinguishable login "
                    "response (same status/body, similar timing) — no obvious enumeration oracle.",
        )

    _forgot_password_enum(ctx, known, absent)


def _forgot_password_enum(ctx: Context, known: str, absent: str) -> None:
    """A forgot/reset endpoint should not confirm whether an email is registered."""
    field = ctx.auth.username_field if "@" in known else "email"
    candidates = [
        r for r in ctx.routes
        if r.method == "POST"
        and any(h in f"{r.path} {r.operation_id}".lower()
                for h in ("forgot", "reset", "password"))
    ]
    if not candidates:
        return
    route = candidates[0]
    try:
        k = ctx.post(route.path, json={field: known, "email": known})
        a = ctx.post(route.path, json={field: absent, "email": absent})
    except Exception as e:  # noqa: BLE001
        ctx.note(f"forgot-password enumeration probe errored: {e}")
        return
    if k.status_code != a.status_code or k.text[:300] != a.text[:300]:
        ctx.finding(
            id="a07-forgot-password-enum",
            owasp="A07", severity="LOW",
            title="Account enumeration via forgot-password response",
            summary=(
                f"POST {route.path} answers differently for a registered vs. an unknown email, "
                "confirming which addresses have accounts. Always return the same generic "
                "'if that address exists, we sent a link' response."
            ),
            evidence=f"known  -> {k.status_code} {k.text[:120]!r}\n"
                     f"absent -> {a.status_code} {a.text[:120]!r}",
            reproduction=f"POST {route.path} with a real vs. a fake email and diff the responses.",
            references=[REFS["A07"]],
            tools=["Burp (Comparer)", "curl"],
        )


def _register(ctx: Context, email: str, password: str, extra: dict | None = None):
    """Register honoring login_style's body shape; extra fields injected as-is."""
    a = ctx.auth
    body: dict = {a.username_field: email, "email": email, a.password_field: password}
    for f in a.register_fields:
        body.setdefault(f, email if "mail" in f.lower() or "name" in f.lower() else "heimdall")
    if extra:
        body.update(extra)
    if a.login_style in ("form", "oauth_password"):
        return ctx.post(a.register_path, data=body)
    return ctx.post(a.register_path, json=body)


def _mass_assignment(ctx: Context) -> None:
    """Inject privileged fields at registration and check if any persist."""
    if not ctx.auth.register_path:
        ctx.note("no register path discovered; mass-assignment check skipped")
        return
    if ctx.safe:
        ctx.note("safe mode: skipping registration mass-assignment (creates an account)")
        return

    injected = {k: v for k, v in _PRIV_FIELDS.items()
                if k not in set(ctx.auth.register_fields)}
    email = f"heimdall.mass+{_next_suffix(ctx)}@example.com"
    password = "Heimdall-Str0ng-Pw!"
    try:
        reg = _register(ctx, email, password, injected)
    except Exception as e:  # noqa: BLE001
        ctx.note(f"mass-assignment registration errored: {e}")
        return
    if reg.status_code >= 300:
        ctx.note(f"mass-assignment: registration rejected (HTTP {reg.status_code}); skipped")
        return

    # Can we verify what actually persisted? We need to log in and read 'me'.
    if not ctx.auth.me_path:
        ctx.finding(
            id="a07-register-mass-assignment",
            owasp="A07", severity="LOW",
            title="Registration mass-assignment unverifiable (no 'me' endpoint)",
            summary=(
                "Privileged fields were injected into the registration body, but with no "
                "current-user echo endpoint the module cannot confirm whether they persisted. "
                f"Injected {sorted(injected)} — verify manually whether the new account gained "
                "any of them."
            ),
            evidence=f"registered {email!r} with extra fields {sorted(injected)} (HTTP "
                     f"{reg.status_code}); response body={reg.text[:200]!r}",
            reproduction=f"Register with role/is_admin/is_superuser set, then inspect the "
                         "account's stored privileges directly.",
            references=[REFS["ps-massassign"], REFS["A07"]],
            tools=["Burp (Repeater)", "curl"],
        )
        return

    try:
        login = _login_attempt(ctx, email, password)
        token = None
        if login.status_code < 300:
            data = login.json() if login.content else {}
            token = data.get(ctx.auth.token_response_field) if isinstance(data, dict) else None
        if not token:
            ctx.note(f"mass-assignment: could not log in as new account (HTTP "
                     f"{login.status_code}); verification skipped")
            return
        me = ctx.get(ctx.auth.me_path, token=token)
        me_data = me.json() if me.content else {}
    except Exception as e:  # noqa: BLE001
        ctx.note(f"mass-assignment verification errored: {e}")
        return

    persisted = _privileged_fields_present(me_data, injected)
    if persisted:
        ctx.finding(
            id="a07-register-mass-assignment",
            owasp="A07", severity="HIGH",
            title="Mass assignment: privileged fields accepted at registration",
            summary=(
                "The registration endpoint bound attacker-supplied privileged fields that are "
                "not part of the public form, and they persisted onto the new account — a "
                "self-service privilege escalation. Bind registration to an explicit allow-list "
                "schema and never trust client-set role/flag fields."
            ),
            evidence=f"registered {email!r} with {sorted(injected)}; 'me' now reports: "
                     f"{persisted}",
            reproduction=f"POST {ctx.auth.register_path} with e.g. is_admin=true / role=admin, "
                         f"log in, then GET {ctx.auth.me_path} — the privilege is present.",
            references=[REFS["ps-massassign"], REFS["A07"], REFS["cheat-authz"]],
            tools=["Burp (Repeater)", "curl", "autorize"],
        )
    else:
        ctx.finding(
            id="a07-register-mass-assignment",
            owasp="A07", severity="SAFE",
            title="Registration ignores injected privileged fields",
            summary=f"Injected {sorted(injected)} at registration, but the new account's 'me' "
                    "response shows none of them took effect — the endpoint is bound to a "
                    "safe field allow-list.",
        )


def _privileged_fields_present(me: dict, injected: dict) -> dict:
    """Which injected privileges actually show up in the 'me' echo?"""
    if not isinstance(me, dict):
        return {}
    hits: dict = {}
    for key, want in injected.items():
        if key not in me:
            continue
        got = me[key]
        if isinstance(want, bool):
            if got is True:
                hits[key] = got
        elif isinstance(got, str) and got.lower() in _ADMIN_TRUTHS:
            hits[key] = got
        elif isinstance(got, (list, tuple)) and any(
                str(x).lower() in _ADMIN_TRUTHS for x in got):
            hits[key] = got
        elif got == want:
            hits[key] = got
    # also catch a generically admin-looking role/type field regardless of match
    for key in ("role", "account_type", "is_admin", "is_superuser"):
        val = me.get(key)
        if key in hits:
            continue
        if val is True or (isinstance(val, str) and val.lower() in _ADMIN_TRUTHS):
            hits[key] = val
    return hits


def _weak_password(ctx: Context) -> None:
    """A trivially weak password should be rejected by a complexity policy."""
    if not ctx.auth.register_path:
        return
    if ctx.safe:
        ctx.note("safe mode: skipping weak-password registration probe")
        return
    email = f"heimdall.weakpw+{_next_suffix(ctx)}@example.com"
    weak = "123"
    try:
        resp = _register(ctx, email, weak)
    except Exception as e:  # noqa: BLE001
        ctx.note(f"weak-password registration errored: {e}")
        return
    if resp.status_code < 300:
        ctx.finding(
            id="a07-weak-password-policy",
            owasp="A07", severity="LOW",
            title="Weak password accepted (no complexity/length policy)",
            summary=(
                f"Registration accepted the password {weak!r} (HTTP {resp.status_code}). With no "
                "minimum length/complexity check, users can pick trivially guessable passwords, "
                "amplifying credential-stuffing and brute-force risk. Enforce a length floor and "
                "screen against known-breached password lists."
            ),
            evidence=f"registered {email!r} with password {weak!r} -> HTTP {resp.status_code}",
            reproduction=f"POST {ctx.auth.register_path} with {ctx.auth.password_field}={weak!r}.",
            references=[REFS["A07"], REFS["cheat-authz"]],
            tools=["curl", "Burp (Repeater)"],
        )
    else:
        ctx.finding(
            id="a07-weak-password-policy",
            owasp="A07", severity="SAFE",
            title="Weak password rejected by policy",
            summary=f"Registration refused the trivial password {weak!r} (HTTP "
                    f"{resp.status_code}) — a length/complexity policy is enforced.",
        )
