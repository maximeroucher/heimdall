"""A01 / API3 — Excessive data exposure (credentials + PII / financial).

APIs routinely over-serialize: a response includes a field the client never
needs — a password hash, an API token, a signing secret — or worse, sensitive
personal / financial data: a credit-card number, a bank IBAN, a Social Security
Number. This module fetches the JSON an endpoint returns and flags it.

The primary detector is BEHAVIOURAL and name-blind: it recognises a sensitive
VALUE by its own shape/checksum, so it fires even when the field is named
innocuously (a card number under ``ref`` still gets caught). It validates
checksums where they exist — Luhn for card PANs, mod-97 for IBANs — to stay
near-zero-FP, and matches specific provider key formats (AWS/Google/GitHub/
Stripe/…), password hashes, PEM keys and JWTs. A secondary, lower-confidence
pass matches field *names* only for values that have no detectable format (a
plaintext password looks like any string, so only its key can betray it).
Token-issuing auth endpoints are excluded, since a token in *their* response is
the point.
"""

from __future__ import annotations

import math
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
# Value formats that are self-evidently sensitive, WHATEVER the field is named —
# this is the hint-free half: detection is by the value's own shape/checksum, so
# it catches leaks even when the field has an innocuous name. Credentials/keys:
_VALUE_PATTERNS = [
    (re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$"), "bcrypt hash"),
    (re.compile(r"^\$argon2[id]{1,2}\$"), "argon2 hash"),
    (re.compile(r"^\$(?:1|5|6)\$"), "crypt(3) hash"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b"), "JWT"),
    # Provider secret/API-key formats (each is specific enough to be near-zero FP)
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\bgh[posru]_[0-9A-Za-z]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "Slack token"),
    (re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "Stripe live key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{40,}\b"), "OpenAI-style secret key"),
    (re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "Twilio key"),
]
# PII / financial value formats — the "bank account / SSN / card" the user cares
# about. Cards and IBANs carry checksums, so we VALIDATE them (not just regex) to
# stay near-zero-FP; an SSN is pattern+range-validated.
_CARD_RE = re.compile(r"(?<![\d.])\d[\d -]{11,17}\d(?![\d.])")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
# Generic high-entropy secrets (an API key / token with no known prefix). Gated
# hard to dodge the obvious benign high-entropy strings (UUIDs, hex hashes).
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TOKENISH = re.compile(r"^[A-Za-z0-9_\-+/=.]{20,128}$")
# The plain name "token" is common and sometimes legitimately public; only treat
# it as sensitive off auth flows, handled via _AUTH_HINTS below.
_WEAK_TOKEN_KEYS = {"token", "auth_token", "bearer", "jwt"}
_AUTH_HINTS = ("auth", "login", "token", "oauth", "session", "sso", "connect")
_MAX_ROUTES = 40
_MAX_DEPTH = 6

# Plaintext-password detection by VALUE (not field name): if a response echoes a
# value we KNOW is a password — a credential the scan authenticated with, or a
# provisioned user's password — it's a definitive plaintext leak. Backed up by a
# short list of *complex* common passwords (kept complex so they can't collide
# with a legitimate role/status/username value like "admin" or "test").
_COMMON_PASSWORDS = {
    "password123", "Password1!", "P@ssw0rd", "Passw0rd!", "changeme123",
    "letmein123", "qwerty123", "welcome123", "iloveyou1", "admin@123",
    "Summer2024!", "Winter2024!",
}


def _known_passwords(ctx: Context) -> set[str]:
    """Real password values the scan holds — every authenticated/provisioned
    principal's password — plus complex common ones. A response containing any of
    these is leaking a plaintext password, confirmed by value with no field-name
    guessing and no false positives."""
    pws = set(_COMMON_PASSWORDS)
    for p in ctx.profile.principals.values():
        if getattr(p, "password", None) and len(p.password) >= 4:
            pws.add(p.password)
    return pws


@module("data-exposure", "Excessive Data Exposure")
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    routes = [r for r in ctx.routes if r.method == "GET"][:_MAX_ROUTES]
    if not routes:
        ctx.note("data-exposure: no GET endpoints to inspect")
        return

    known_pw = _known_passwords(ctx)
    hits: list[dict] = []
    probed = 0
    for r in routes:
        probed += 1
        _inspect(ctx, r, token, hits, known_pw)

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


# Standard PUBLIC protocol-metadata endpoints: their content (public keys, config
# URLs, supported algorithms) is meant to be world-readable, so high-entropy
# values there — a key id, an RSA modulus — are not data leaks.
_PUBLIC_METADATA_RE = re.compile(
    r"(?:^|/)\.well-known/|/jwks(?:\.json)?(?:$|/|\?)|openid-configuration|"
    r"oauth-authorization-server", re.I)
# PRIVATE JWK members — these must never appear in a PUBLISHED key set; if one
# does, it IS a critical leak and stays flagged even on a metadata endpoint.
_JWK_PRIVATE_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


def _is_public_metadata(route) -> bool:
    return bool(_PUBLIC_METADATA_RE.search(route.path))


# Claims that identify WHO a token belongs to. `sub` is included only when it
# isn't one of these generic token-TYPE markers (RealWorld sets sub="access").
_IDENTITY_CLAIMS = ("username", "preferred_username", "email", "user_id",
                    "uid", "userid", "name", "nickname", "login")
_GENERIC_SUB = frozenset({"access", "refresh", "id_token", "auth", "bearer", "token"})


def _is_own_token(value, actor_token) -> bool:
    """True if ``value`` is a JWT carrying the SAME identity as the caller's own
    token — the caller's credential echoed back on a "get current user" / token-
    refresh endpoint (e.g. RealWorld's GET /api/user, or any /users/me that
    returns ``token``), which is by design, not a leak. Another user's token
    (different identity) is NOT own, so a genuine cross-user token leak still
    flags. Requires the response to have been fetched with the caller's token."""
    if not actor_token:
        return False
    sval = str(value)
    if sval == actor_token:
        return True
    from ..discovery.auth import decode_jwt
    a, b = decode_jwt(sval), decode_jwt(actor_token)
    if not a or not b:
        return False
    ac, bc = a[1], b[1]
    for claim in _IDENTITY_CLAIMS:
        av = ac.get(claim)
        if av and av == bc.get(claim):
            return True
    asub = str(ac.get("sub", ""))
    if asub and asub == str(bc.get("sub", "")) and asub.lower() not in _GENERIC_SUB:
        return True
    return False


def _inspect(ctx: Context, route, token, hits: list[dict], known_pw: set) -> None:
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
    public_meta = _is_public_metadata(route)
    for keypath, key, value in _walk(data):
        # A public protocol-metadata endpoint (JWKS, OpenID discovery) publishes
        # PUBLIC keys/config by design — a high-entropy `kid`, modulus `n`, or a
        # config URL there is not a leak. Still flag a PRIVATE-key JWK component
        # (`d`/`p`/`q`/…) — those must NEVER appear in a published JWKS.
        if public_meta and key.lower() not in _JWK_PRIVATE_FIELDS:
            continue
        res = _sensitive(key, value, auth_route, known_pw)
        if res:
            if _is_own_token(value, token):
                continue     # caller's own token echoed on a /me / refresh response
            reason, severity = res
            hits.append({"route": route, "keypath": keypath, "key": key,
                         "reason": reason, "severity": severity,
                         "sample": _redact(value)})
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


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    rearranged = s[4:] + s[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _value_leak(sval: str) -> str | None:
    """Behavioural: is this VALUE itself sensitive, by format/checksum? Never
    inspects the field name."""
    for pat, label in _VALUE_PATTERNS:
        if pat.search(sval):
            return label
    # Credit-card PAN: a plausible-length run of digits that passes the Luhn
    # checksum and starts with a real card major-industry digit (3-6).
    for m in _CARD_RE.finditer(sval):
        digits = m.group().replace(" ", "").replace("-", "")
        if 13 <= len(digits) <= 19 and digits[0] in "3456" \
                and len(set(digits)) > 1 and _luhn_ok(digits):
            return "credit-card number (Luhn-valid)"
    # IBAN: country+check digits then a valid mod-97 checksum. IBANs are commonly
    # written grouped in 4s with spaces, so validate a whitespace-stripped copy
    # too (the mod-97 check keeps this near-zero-FP).
    for candidate in {sval, re.sub(r"\s+", "", sval)}:
        for m in _IBAN_RE.finditer(candidate):
            if _iban_ok(m.group()):
                return "IBAN bank account (checksum-valid)"
    if _SSN_RE.search(sval):
        return "US Social Security Number"
    return None


def _shannon(s: str) -> float:
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# base64 magic prefixes of common binary FILES (image/pdf/zip/svg) — high entropy
# but not secrets: PNG / JPEG / GIF / PDF / ZIP(docx…) / WEBP / SVG.
_B64_FILE_MAGIC = ("iVBORw0KGgo", "/9j/", "R0lGOD", "JVBERi0", "UEsDBB", "UklGR", "PHN2Zw")


def _entropy_secret(sval: str) -> bool:
    """A random-looking token/key with no known prefix. Gated to exclude the
    common benign high-entropy strings: UUIDs and single-case hex hashes are
    ruled out by requiring MIXED character classes (upper+lower+digit); base64
    file/image data is ruled out by its magic prefix."""
    if sval.startswith(_B64_FILE_MAGIC):   # base64-encoded file/image, not a secret
        return False
    if not _TOKENISH.match(sval) or _UUID_RE.match(sval):
        return False
    if not (any(c.isupper() for c in sval) and any(c.islower() for c in sval)
            and any(c.isdigit() for c in sval)):
        return False
    return _shannon(sval) >= 3.5


# Schema/UI-metadata fields hold ILLUSTRATIVE values (a form placeholder like
# "sk-..." or an example card "4111 1111 1111 1111"), not real data — so their
# values must not be judged as leaked secrets by format/entropy.
_META_FIELDS = frozenset({
    "placeholder", "example", "examples", "sample", "hint", "default", "pattern",
    "format", "mask", "template", "demo", "eg", "e_g", "prefix_example",
})
# token-bearing field names — a token in the response of a token-ISSUING auth
# route (login/refresh/token) is the whole point, not a leak
_TOKEN_FIELDS = frozenset({
    "access_token", "refresh_token", "token", "id_token", "jwt", "bearer",
    "api_key", "apikey", "auth_token", "session_token",
})


def _sensitive(key: str, value, auth_route: bool, known_pw: set):
    """Return (reason, severity) or None. Value format/checksum matches are
    HIGH-confidence; entropy and name-based matches are MEDIUM."""
    if value is None or value == "" or value is True or value is False:
        return None
    kl = key.lower()
    if kl in _META_FIELDS:            # illustrative example, not a real value
        return None
    sval = str(value)
    # 1) the VALUE itself is sensitive by format/checksum — behavioural, name-blind
    #    (credentials, provider keys, card numbers, IBANs, SSNs). HIGH confidence.
    # a token-issuing auth route (login/refresh/token) returns tokens BY DESIGN —
    # its JWT/token value (or token-named field) is expected, not a leak. Other
    # sensitive values (passwords, cards, PII) below still flag even here.
    token_expected = auth_route and (kl in _TOKEN_FIELDS or "token" in kl)
    vleak = _value_leak(sval)
    if vleak:
        if token_expected and ("jwt" in vleak.lower() or "token" in vleak.lower()):
            return None
        return f"value is a {vleak}", "HIGH"
    # 2) the VALUE equals a password we know is a password — a credential the scan
    #    authenticated with, or a complex common one. Definitive plaintext leak,
    #    matched by value (no field name), so it fires even under an odd key.
    if sval in known_pw:
        return "value is a plaintext password (matches a known/used credential)", "HIGH"
    # 3) a high-entropy token/key with no known format — behavioural, name-blind.
    if _entropy_secret(sval):
        if token_expected:           # a token on a token-issuing route is expected
            return None
        return "value is a high-entropy secret-like string (probable token/key)", "MEDIUM"
    # 4) field NAME denotes a secret — last-resort fallback for a plaintext value
    #    we neither recognise as a format nor know as a credential.
    if kl in _SECRET_KEYS:
        return f"field '{key}' (secret-bearing) is present in the response", "MEDIUM"
    # 4) a bare 'token'/'jwt' key — sensitive unless this is a token-issuing route
    if kl in _WEAK_TOKEN_KEYS and not auth_route and len(sval) >= 12:
        return f"field '{key}' exposes a token outside an auth flow", "MEDIUM"
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
    severity = "HIGH" if any(h["severity"] == "HIGH" for h in hits) else "MEDIUM"
    ctx.finding(
        id="a01-excessive-data-exposure",
        owasp="A01", severity=severity,
        title=(f"Sensitive data exposed in {r.method} {r.path} response"
               + (f" (+{len(hits) - 1} more)" if len(hits) > 1 else "")),
        summary=(
            "An API response ships data no client should receive — a credential "
            "(password hash, token, private key), a provider API key, or "
            "personal/financial data (a Luhn-valid card number, a checksum-valid "
            "IBAN, an SSN). Most of these are matched by the value's own "
            "format/checksum, so the leak is real regardless of how the field is "
            "named. Impact ranges from offline cracking / account takeover (a "
            "leaked hash or token) to PCI/PII breach (a card or SSN in a response). "
            "Fix at the serializer: define an explicit response schema (FastAPI "
            "`response_model` with sensitive fields excluded / `Field(exclude=True)`) "
            "rather than returning ORM objects directly, and never place raw "
            "card/account numbers in an API response."
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
        title="No sensitive data found in API responses",
        summary=(
            f"Walked the JSON of {probed} GET response(s) for sensitive VALUES "
            "(password/argon2/bcrypt hashes, PEM keys, JWTs, provider API keys, "
            "Luhn-valid card numbers, checksum-valid IBANs, SSNs, high-entropy "
            "secrets) and secret-bearing field names; none were exposed, "
            "consistent with explicit response schemas that strip sensitive fields. "
            "Fields only returned to specific roles, and write-path responses, "
            "still merit manual review."
        ),
        references=[REFS["A01"], REFS["api3"]],
    )
