"""A01 / API3 — Excessive data exposure.

APIs routinely over-serialize: a response model includes a field the client
never needs — a password hash, an API token, a signing secret, an OAuth
refresh token — and it ships to every caller. This is the object-property side
of access control (OWASP API3), and it's cheap to detect black-box: fetch the
JSON an endpoint returns and look for property *names* that denote secrets, and
property *values* that are unmistakably credentials (bcrypt/argon2 hashes, PEM
keys, JWTs).

Precision comes from only flagging high-confidence signals: a key literally
named ``password_hash`` / ``secret`` / ``refresh_token`` carrying a non-empty
value, or a value matching a credential format — not merely "there's an email
in the response" (returning your own email is usually fine). Token-issuing auth
endpoints are excluded, since a token in *their* response is the point.
"""

from __future__ import annotations

import re

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

# Property names that should essentially never appear in a response body.
_SECRET_KEYS = {
    "password", "passwd", "pwd", "password_hash", "hashed_password", "pwd_hash",
    "secret", "secret_key", "client_secret", "private_key", "signing_key",
    "api_key", "apikey", "access_token", "refresh_token", "session_token",
    "otp_secret", "totp_secret", "mfa_secret", "twofa_secret", "salt",
    "seed_phrase", "mnemonic", "ssn", "social_security", "card_number", "pan",
    "cvv", "cvc", "security_code", "encryption_key", "recovery_code",
}
# Value formats that are self-evidently credentials, whatever the key is called.
_VALUE_PATTERNS = [
    (re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$"), "bcrypt hash"),
    (re.compile(r"^\$argon2[id]{1,2}\$"), "argon2 hash"),
    (re.compile(r"^\$(?:1|5|6)\$"), "crypt(3) hash"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]+$"), "JWT"),
]
# The plain name "token" is common and sometimes legitimately public; only treat
# it as sensitive off auth flows, handled via _AUTH_HINTS below.
_WEAK_TOKEN_KEYS = {"token", "auth_token", "bearer", "jwt"}
_AUTH_HINTS = ("auth", "login", "token", "oauth", "session", "sso", "connect")
_MAX_ROUTES = 40
_MAX_DEPTH = 6


@module("data-exposure", "Excessive Data Exposure")
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    routes = [r for r in ctx.routes if r.method == "GET"][:_MAX_ROUTES]
    if not routes:
        ctx.note("data-exposure: no GET endpoints to inspect")
        return

    hits: list[dict] = []
    probed = 0
    for r in routes:
        probed += 1
        _inspect(ctx, r, token, hits)

    ctx.note(f"data-exposure: inspected {probed} GET response(s); "
             f"{len(hits)} exposed a sensitive field")
    if hits:
        _report(ctx, hits)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


def _is_auth_route(route) -> bool:
    hay = (route.path + " " + route.operation_id).lower()
    return any(h in hay for h in _AUTH_HINTS)


def _inspect(ctx: Context, route, token, hits: list[dict]) -> None:
    path = route.fill_path({p: "1" for p in route.path_params})
    try:
        resp = ctx.get(path, token=token, timeout=10, retry_429=False)
    except requests.RequestException:
        return
    ctype = resp.headers.get("Content-Type", "").lower()
    if resp.status_code >= 400 or "json" not in ctype:
        return
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return
    auth_route = _is_auth_route(route)
    for keypath, key, value in _walk(data):
        reason = _sensitive(key, value, auth_route)
        if reason:
            hits.append({"route": route, "keypath": keypath, "key": key,
                         "reason": reason, "sample": _redact(value)})
            if len([h for h in hits if h["route"] is route]) >= 4:
                break  # a few per route is enough to make the point


def _walk(obj, prefix="", depth=0):
    """Yield (dotted_keypath, key, value) for every scalar leaf."""
    if depth > _MAX_DEPTH:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk(v, kp, depth + 1)
            else:
                yield kp, str(k), v
    elif isinstance(obj, list):
        for item in obj[:20]:
            yield from _walk(item, prefix + "[]", depth + 1)


def _sensitive(key: str, value, auth_route: bool) -> str | None:
    if value is None or value == "" or value is True or value is False:
        return None
    kl = key.lower()
    sval = str(value)
    # 1) value looks like a credential, regardless of the key name
    for pat, label in _VALUE_PATTERNS:
        if pat.search(sval):
            return f"value is a {label}"
    # 2) key name denotes a secret
    if kl in _SECRET_KEYS:
        return f"field '{key}' (secret-bearing) is present in the response"
    # 3) a bare 'token'/'jwt' key — sensitive unless this is a token-issuing route
    if kl in _WEAK_TOKEN_KEYS and not auth_route and len(sval) >= 12:
        return f"field '{key}' exposes a token outside an auth flow"
    return None


def _redact(value) -> str:
    s = str(value)
    return (s[:6] + "…" + f"[{len(s)} chars]") if len(s) > 10 else "[short value]"


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx: Context, hits: list[dict]) -> None:
    lead = hits[0]
    r = lead["route"]
    lines = []
    for h in hits[:15]:
        hr = h["route"]
        lines.append(f"  {hr.method} {hr.path}  →  {h['keypath']}  "
                     f"({h['reason']}; sample {h['sample']})")
    ctx.finding(
        id="a01-excessive-data-exposure",
        owasp="A01", severity="HIGH",
        title=(f"Sensitive field exposed in {r.method} {r.path} response"
               + (f" (+{len(hits) - 1} more)" if len(hits) > 1 else "")),
        summary=(
            "An API response over-serializes a credential-class property — a "
            "password hash, token, private key or other secret that no client "
            "should receive. Anyone authorized to read the object also reads the "
            "secret: password hashes enable offline cracking, an exposed token / "
            "refresh token is an immediate account takeover, and a private key is "
            "game over. Fix at the serializer: define an explicit response schema "
            "(FastAPI `response_model` with the secret fields excluded / "
            "`Field(exclude=True)`) rather than returning ORM objects directly."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=f"{r.method} {r.path}  (authenticated read)",
        reproduction=(f"GET {r.path} as any authorized user and read "
                      f"{lead['keypath']} from the JSON response."),
        references=[REFS["A01"], REFS["api3"],
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "REST_Security_Cheat_Sheet.html"],
        tools=["Burp Suite", "curl | jq"],
    )


def _report_safe(ctx: Context, probed: int) -> None:
    ctx.finding(
        id="a01-data-exposure-safe",
        owasp="A01", severity="SAFE",
        title="No credential-class fields found in API responses",
        summary=(
            f"Walked the JSON of {probed} GET response(s) for secret-bearing "
            "property names (password_hash, token, secret, private_key, …) and "
            "credential-format values (bcrypt/argon2 hashes, PEM keys, JWTs); none "
            "were exposed, consistent with explicit response schemas that strip "
            "sensitive fields. Property-level authorization on write paths and "
            "fields only returned to specific roles still merit manual review."
        ),
        references=[REFS["A01"], REFS["api3"]],
    )
