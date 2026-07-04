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
        except ValueError:
            return None
        if not isinstance(body, dict):
            return None  # a "me" route that returns a list/scalar isn't an identity echo
        return str(body.get("id") or body.get("user_id") or body.get("sub") or "") or None
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


def _synth_field(name: str, spec: dict, *, ident: str, username: str,
                 password: str) -> object:
    """Invent a plausible value for one register-body field, from its name and
    JSON-schema type/format. Lets self-registration satisfy required fields a
    given app demands beyond the canonical email/username/password (e.g. DVR's
    required ``phone_number``), instead of 422-ing and yielding no attacker."""
    low = name.lower()
    fmt = str(spec.get("format", "")).lower()
    # unwrap Optional[...] / anyOf so a nullable field still gets a typed guess
    typ = spec.get("type")
    if not typ:
        for sub in spec.get("anyOf", []) + spec.get("oneOf", []):
            if isinstance(sub, dict) and sub.get("type") not in (None, "null"):
                typ = sub.get("type")
                fmt = fmt or str(sub.get("format", "")).lower()
                break
    if "enum" in spec and isinstance(spec["enum"], list) and spec["enum"]:
        return spec["enum"][0]
    # name/format-driven canonical values first
    if "email" in low or fmt == "email":
        return ident
    if any(k in low for k in ("password", "passwd", "pwd")):
        return password
    if "username" in low or low in ("user", "login", "handle"):
        return username
    if "phone" in low or "mobile" in low or "tel" in low:
        return "+15555550123"
    if fmt in ("uri", "url") or "url" in low:
        return "https://example.com"
    if fmt == "uuid":
        return "00000000-0000-0000-0000-000000000000"
    if fmt in ("date-time", "datetime"):
        return "2026-01-01T00:00:00Z"
    if fmt == "date":
        return "2026-01-01"
    if any(k in low for k in ("first", "given")):
        return "Heim"
    if any(k in low for k in ("last", "family", "surname")):
        return "Dall"
    if "name" in low:
        return "Heimdall"
    # type-driven fallback
    if typ == "integer":
        return 1
    if typ == "number":
        return 1
    if typ == "boolean":
        return False
    if typ == "array":
        return []
    if typ == "object":
        return {}
    return "heimdall"


def _register_attacker(http: HttpClient, profile: AppProfile) -> Principal | None:
    ap = profile.auth
    ident = "heimdall.attacker@example.com"
    username = "heimdall_attacker"
    password = "Heimdall!Attacker#2026"
    fields = {f.lower(): f for f in ap.register_fields}
    schema = ap.register_schema or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    props = props if isinstance(props, dict) else {}
    required = schema.get("required") if isinstance(schema, dict) else None
    required = required if isinstance(required, list) else []

    payload: dict = {}
    # Fill EVERY required field with a typed synthetic value so apps that demand
    # extra fields (phone, dob, …) still register. Canonical creds win by name.
    for fname in required:
        spec = props.get(fname, {}) if isinstance(props.get(fname), dict) else {}
        payload[fname] = _synth_field(fname, spec, ident=ident,
                                      username=username, password=password)
    # Always ensure the login triple is present (some apps under-declare required).
    if "email" in fields:
        payload[fields["email"]] = ident
    if "username" in fields:
        payload[fields["username"]] = username
    if "password" in fields:
        payload[fields["password"]] = password
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
