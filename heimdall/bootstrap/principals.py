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
        v = body.get(f)
        if isinstance(v, str) and v:      # a STRING token, never a nested object
            return v
    # nested token envelopes: {"token": {"access_token": …}} (this is common),
    # {"data": {...}} / {"tokens": {...}} / {"user": {...}} (RealWorld)
    for wrap in ("token", "data", "tokens", "result", "user", "auth", "session"):
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
            body = {uf: ident, pf: password}
            if ap.login_wrapper:
                body = {ap.login_wrapper: body}   # {"user": {...}} envelope
            r = http.post(ap.login_path, json=body)
        # 2xx OR a 3xx redirect (cookie-session logins commonly 302 to a dashboard)
        if r.status_code < 400:
            try:
                tok = _extract_token(r.json())
            except ValueError:
                tok = None
            if tok:
                return tok
            # Cookie/session auth: no token in the body, but a session cookie was
            # set — carry the cookie value as the principal's credential. Also
            # auto-upgrades apps whose scheme wasn't declared as a cookie scheme.
            cookie_val = _session_cookie(profile, r, http)
            if cookie_val:
                return cookie_val
    return None


def _session_cookie(profile: AppProfile, resp, http: HttpClient | None = None) -> str | None:
    # A login cookie set on a 302 lands in the SESSION JAR after the redirect is
    # followed (not the final response), so merge the response, its redirect
    # history, and the persistent jar.
    jar: dict = {}
    for c in list(resp.cookies) + [c for h in getattr(resp, "history", []) for c in h.cookies]:
        jar[c.name] = c.value
    if http is not None:
        for c in http.s.cookies:
            jar.setdefault(c.name, c.value)
    if not jar:
        return None
    named = profile.auth.credential_name
    if named and named in jar:
        return jar[named]
    # pick the most session-like cookie (ignore obvious non-auth cookies)
    pref = next((n for n in jar if any(
        k in n.lower() for k in ("session", "sess", "sid", "auth", "token"))
        and "csrf" not in n.lower() and "xsrf" not in n.lower()), None)
    name = pref or next(iter(jar))
    val = jar[name]
    if profile.auth.auth_kind != "cookie":
        profile.auth.auth_kind = "cookie"
        profile.auth.credential_name = name
        profile.notes.append(f"detected cookie-session auth (cookie '{name}')")
    # Don't let the login cookie linger in the shared jar — it would silently
    # authenticate "unauthenticated" probes (false no-auth SAFE / BFLA misses).
    # It is re-attached explicitly via the Cookie header for authed requests.
    if http is not None:
        http.s.cookies.clear()
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


# Authorization value prefixes to try when the detected scheme is rejected. ""
# means the raw token with no prefix (apiKey-in-Authorization apps).
_SCHEME_CANDIDATES = ("Bearer", "Token", "JWT", "")


def _secured_oracle(http: HttpClient, profile: AppProfile) -> str | None:
    """A secured GET route that rejects an anonymous request (>=400) — usable to
    tell whether a token is being accepted, independent of which module asks."""
    if getattr(profile.auth, "_oracle", "unset") != "unset":
        return profile.auth._oracle
    cands = []
    if profile.auth.me_path:
        cands.append(profile.auth.me_path)
    cands += [r.path for r in profile.routes.secured()
              if r.method == "GET" and not r.has_path_param][:15]
    found = None
    for path in cands:
        try:
            if http.get(path).status_code >= 400:  # enforces auth when anonymous
                found = path
                break
        except Exception:  # noqa: BLE001
            continue
    profile.auth._oracle = found
    return found


def _calibrate_scheme(http: HttpClient, profile: AppProfile, token: str | None) -> None:
    """Find the Authorization scheme the server actually accepts.

    OpenAPI often declares an ``apiKey``-in-``Authorization`` (or a bare bearer)
    scheme without pinning the prefix, but the app wants a specific one — e.g. the
    RealWorld/Conduit convention ``Authorization: Token <jwt>`` (Bearer 403s). If
    the detected scheme is rejected, replay a known-good token against a secured
    route with each candidate prefix and lock in the one that works, so every
    module authenticates correctly."""
    if not token or getattr(profile.auth, "_scheme_calibrated", False):
        return
    oracle = _secured_oracle(http, profile)
    if not oracle:
        return
    if http.get(oracle, token=token).status_code < 400:
        profile.auth._scheme_calibrated = True  # detected scheme already works
        return
    for scheme in _SCHEME_CANDIDATES:
        raw = f"{scheme} {token}".strip()
        try:
            if http.get(oracle, raw_authorization=raw).status_code < 400:
                if scheme:
                    profile.auth.auth_kind = "bearer"
                    profile.auth.header_scheme = scheme
                else:
                    profile.auth.auth_kind = "apikey_header"
                    profile.auth.credential_name = "Authorization"
                profile.auth._scheme_calibrated = True
                profile.notes.append(
                    f"calibrated Authorization scheme to '{scheme or '<raw token>'}' "
                    "(the detected scheme was rejected by the server)")
                return
        except Exception:  # noqa: BLE001
            continue


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
        if tok:
            _calibrate_scheme(http, profile, tok)  # lock in the working header scheme
            http = _client(profile)
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
            # A SECOND self-registered low-priv user (a "victim") so cross-principal
            # BOLA can be tested WITHOUT DB --provision: attacker A tries to read/
            # modify victim B's own objects. Only if it carries a distinct user id.
            victim = _register_attacker(http, profile, label="attacker2", suffix="2")
            if victim and victim.user_id and victim.user_id != atk.user_id:
                principals["attacker2"] = victim

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


def _register_attacker(http: HttpClient, profile: AppProfile, *,
                       label: str = "attacker", suffix: str = "") -> Principal | None:
    ap = profile.auth
    # UNIQUE identity per run — a fixed email collides with a user left in a
    # persistent DB by an earlier run (registration then fails, yielding no
    # principal and silently degrading every authed check).
    import uuid
    tag = uuid.uuid4().hex[:8]
    ident = f"heimdall.attacker{suffix}.{tag}@example.com"
    username = f"heimdall_attacker{suffix}_{tag}"
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

    body = {ap.register_wrapper: payload} if ap.register_wrapper else payload
    r = http.post(ap.register_path, json=body)
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
    _calibrate_scheme(http, profile, tok)   # lock in the working header scheme
    http = _client(profile)
    p = Principal(label=label, role="attacker", email=ident, username=username,
                  password=password, token=tok)
    p.user_id = _whoami(http, profile, tok)
    if not profile.auth.jwt_alg:
        auth_detect.enrich_with_token(profile.auth, tok)
    return p
