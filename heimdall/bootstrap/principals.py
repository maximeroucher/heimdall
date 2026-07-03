"""Turn credentials into authenticated ``Principal``s via the *discovered* flow.

Two sources of principals:
  * supplied credentials (privileged accounts you can't self-register) — from the
    target config; each becomes a Principal with the role you label it.
  * a self-registered low-privilege "attacker" — created through the detected
    register endpoint so cross-tenant / privilege-escalation tests have a subject.

Login adapts to the detected ``login_style`` (json / form / oauth_password).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.http import HttpClient
from ..core.model import AppProfile, Principal
from ..discovery import auth as auth_detect


@dataclass
class Cred:
    label: str
    role: str
    identifier: str          # username or email
    password: str


_TOKEN_FIELDS = ("access_token", "token", "id_token", "jwt", "accessToken")


def _extract_token(body: dict) -> str | None:
    if not isinstance(body, dict):
        return None
    for f in _TOKEN_FIELDS:
        if body.get(f):
            return body[f]
    # nested {"data": {...}} or {"tokens": {...}}
    for wrap in ("data", "tokens", "result"):
        inner = body.get(wrap)
        if isinstance(inner, dict):
            t = _extract_token(inner)
            if t:
                return t
    return None


def login(http: HttpClient, profile: AppProfile, ident: str, password: str) -> str | None:
    ap = profile.auth
    if not ap.login_path:
        return None
    uf, pf = ap.username_field, ap.password_field
    styles = [ap.login_style, "json", "form"]  # try detected first, then fall back
    tried = set()
    for style in styles:
        if style in tried:
            continue
        tried.add(style)
        if style in ("form", "oauth_password"):
            data = {uf: ident, pf: password}
            if style == "oauth_password":
                data["grant_type"] = "password"
                if ap.scopes_field:
                    data[ap.scopes_field] = "API"
            r = http.post(ap.login_path, data=data)
        else:
            r = http.post(ap.login_path, json={uf: ident, pf: password})
        if r.status_code == 200:
            try:
                tok = _extract_token(r.json())
            except ValueError:
                tok = None
            if tok:
                return tok
            # Cookie/session auth: no token in the body, but a session cookie was
            # set — carry the cookie value as the principal's credential. Also
            # auto-upgrades apps whose scheme wasn't declared as a cookie scheme.
            cookie_val = _session_cookie(profile, r)
            if cookie_val:
                return cookie_val
    return None


def _session_cookie(profile: AppProfile, resp) -> str | None:
    jar = resp.cookies
    if not jar:
        return None
    named = profile.auth.credential_name
    if named and named in jar:
        val = jar.get(named)
    else:
        # pick the most session-like cookie
        pref = next((c.name for c in jar if any(
            k in c.name.lower() for k in ("session", "sess", "sid", "auth", "token"))), None)
        name = pref or next(iter(jar.keys()))
        val = jar.get(name)
        if profile.auth.auth_kind != "cookie":
            profile.auth.auth_kind = "cookie"
            profile.auth.credential_name = name
            profile.notes.append(f"detected cookie-session auth (cookie '{name}')")
    return val


def _whoami(http: HttpClient, profile: AppProfile, token: str) -> str | None:
    if not profile.auth.me_path:
        return None
    r = http.get(profile.auth.me_path, token=token)
    if r.status_code == 200:
        try:
            body = r.json()
            return str(body.get("id") or body.get("user_id") or body.get("sub") or "") or None
        except ValueError:
            return None
    return None


def _client(profile: AppProfile) -> HttpClient:
    return HttpClient(profile.base_url, scheme=profile.auth.header_scheme,
                      auth_kind=profile.auth.auth_kind,
                      credential_name=profile.auth.credential_name)


def bootstrap(profile: AppProfile, creds: list[Cred], *,
              make_attacker: bool = True) -> dict[str, Principal]:
    http = _client(profile)
    principals: dict[str, Principal] = {}

    # 1. supplied privileged / role credentials
    for c in creds:
        tok = login(http, profile, c.identifier, c.password)
        # login() may have auto-detected cookie/api-key auth — resync the client.
        http.auth_kind, http.credential_name = profile.auth.auth_kind, profile.auth.credential_name
        # API-key apps have no login flow: the supplied secret IS the key.
        if not tok and profile.auth.auth_kind in ("apikey_header", "apikey_query", "basic"):
            tok = c.password
        p = Principal(label=c.label, role=c.role, email=c.identifier,
                      username=c.identifier, password=c.password, token=tok, supplied=True)
        if tok:
            p.user_id = _whoami(http, profile, tok)
            if not profile.auth.is_jwt and not profile.auth.jwt_alg:
                auth_detect.enrich_with_token(profile.auth, tok)
        else:
            profile.notes.append(f"login failed for supplied principal '{c.label}' ({c.identifier})")
        principals[c.label] = p

    # 2. self-registered attacker (low privilege)
    if make_attacker and profile.auth.register_path:
        atk = _register_attacker(http, profile)
        if atk:
            principals["attacker"] = atk

    profile.principals = principals
    return principals


def _register_attacker(http: HttpClient, profile: AppProfile) -> Principal | None:
    ap = profile.auth
    ident = "heimdall.attacker@example.com"
    username = "heimdall_attacker"
    password = "Heimdall!Attacker#2026"
    fields = {f.lower(): f for f in ap.register_fields}
    payload: dict = {}
    if "email" in fields:
        payload[fields["email"]] = ident
    if "username" in fields:
        payload[fields["username"]] = username
    if "password" in fields:
        payload[fields["password"]] = password
    # sensible defaults for other required-ish fields
    for maybe, val in (("name", "Heimdall"), ("full_name", "Heimdall Attacker"),
                       ("firstname", "Heim"), ("lastname", "Dall")):
        if maybe in fields:
            payload[fields[maybe]] = val
    if not payload:
        payload = {"email": ident, "username": username, "password": password}

    r = http.post(ap.register_path, json=payload)
    tok = None
    if r.status_code in (200, 201):
        try:
            tok = _extract_token(r.json())
        except ValueError:
            tok = None
    if not tok:
        tok = login(http, profile, ident, password) or login(http, profile, username, password)
    if not tok:
        profile.notes.append("attacker self-registration did not yield a token "
                             "(may need email activation) — cross-tenant tests limited")
        return None
    p = Principal(label="attacker", role="attacker", email=ident, username=username,
                  password=password, token=tok)
    p.user_id = _whoami(http, profile, tok)
    if not profile.auth.jwt_alg:
        auth_detect.enrich_with_token(profile.auth, tok)
    return p
