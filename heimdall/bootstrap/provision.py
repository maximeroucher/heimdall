"""Self-provisioning: create the test data the modules need, in a DB Heimdall owns.

Rather than fight an app's email-activation flow, Heimdall spawns a throwaway
database (see ``testdb.py``), boots the target against it, then inserts the
principals it needs *directly*. The robust, app-agnostic trick is to **clone an
existing seeded user row**: copy a real row, give it a new id, a unique email
(keeping the original's domain so domain-based rules still pass) and a bcrypt
password hash — every app-specific NOT-NULL / FK / enum column comes along for
free from the template row. Low-privilege clones get any ``is_admin`` /
``is_super_admin`` flag cleared; an admin clone gets it set.

The resulting accounts log in through the app's real login endpoint, so the
tokens are genuine. When the app issues scope-limited login tokens (some OAuth
apps do), pair this with ``minting`` to obtain properly-scoped tokens.

DB strategies must target a disposable database — never a real one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from ..core.http import HttpClient
from ..core.model import AppProfile, Principal
from ..discovery import auth as auth_detect
from .principals import login

# Column/table name heuristics for locating the authenticatable user table.
_EMAIL_HINTS = ("email", "mail", "username", "login")
_PWHASH_HINTS = ("password_hash", "hashed_password", "password", "passwd", "pwd_hash")
_ADMIN_FLAGS = ("is_super_admin", "is_superuser", "is_admin", "is_staff", "superuser", "admin")
_ACTIVE_FLAGS = ("is_active", "active", "is_verified", "verified", "is_confirmed",
                 "confirmed", "enabled", "email_verified")
_SKIP_TABLE = ("unconfirmed", "pending", "recover", "invitation", "reset", "migration",
               "temp", "audit", "log", "history", "session", "token")


@dataclass
class ProvisionRequest:
    low_priv: int = 2                     # distinct low-privilege users
    admins: int = 0                       # admin users to also mint (via admin flag)
    password: str = "Heimdall!Prov#2026"
    db_url: str | None = None             # throwaway DB SQLAlchemy URL
    user_table: str | None = None         # override auto-detection
    email_domain: str | None = None       # override cloned email domain
    command: str | None = None            # escape hatch (prints principals as JSON)
    command_cwd: str | None = None


@dataclass
class ProvisionResult:
    principals: list[Principal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def provision(profile: AppProfile, req: ProvisionRequest) -> ProvisionResult:
    res = ProvisionResult()
    if req.command:
        return _provision_via_command(req, res)
    if not req.db_url:
        res.notes.append("no db_url given; DB self-provisioning unavailable")
        return res
    try:
        return _provision_via_db(profile, req, res)
    except Exception as exc:  # noqa: BLE001 — provisioning must never abort the run
        res.notes.append(f"DB provisioning failed: {type(exc).__name__}: {exc}")
        return res


class _ProvisionError(Exception):
    pass


def _engine(db_url: str):
    try:
        from sqlalchemy import create_engine
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise _ProvisionError("SQLAlchemy required for DB provisioning "
                              "(pip install 'heimdall-pentest[full]')") from exc
    return create_engine(db_url)


def _bcrypt_hash(password: str) -> str:
    try:
        import bcrypt
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise _ProvisionError("bcrypt required for DB provisioning "
                              "(pip install 'heimdall-pentest[full]')") from exc
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def _find_user_table(insp, override: str | None) -> tuple[str, dict]:
    """Return (table, {role: colname}) for the authenticatable user table."""
    candidates = []
    for table in insp.get_table_names():
        low = table.lower()
        if override and low != override.lower():
            continue
        if not override and any(s in low for s in _SKIP_TABLE):
            continue
        columns = insp.get_columns(table)
        cols = {c["name"].lower(): c["name"] for c in columns}
        email = next((cols[h] for h in _EMAIL_HINTS if h in cols), None)
        pw = next((cols[h] for h in _PWHASH_HINTS if h in cols), None)
        # PK cross-dialect: get_columns()['primary_key'] is SQLite-only; Postgres
        # exposes it via get_pk_constraint. Fall back to an 'id' column.
        pk_cols = (insp.get_pk_constraint(table) or {}).get("constrained_columns") or []
        pk = pk_cols[0] if pk_cols else (cols.get("id"))
        if not (email and pw and pk):
            continue
        # score: exact user-ish name + presence of an admin flag
        score = 0
        if any(t in low for t in ("user", "account", "member")):
            score += 2
        if low in ("user", "users", "core_user", "auth_user", "accounts"):
            score += 3
        admin = next((cols[f] for f in _ADMIN_FLAGS if f in cols), None)
        active = next((cols[f] for f in _ACTIVE_FLAGS if f in cols), None)
        # UNIQUE string columns (username/login/...) must get a distinct value per
        # clone or the insert collides — collect them so the inserter can vary them.
        coltype = {c["name"]: str(c["type"]).upper() for c in columns}
        uniq: set = set()
        for u in insp.get_unique_constraints(table):
            uniq |= set(u.get("column_names") or [])
        for ix in insp.get_indexes(table):
            if ix.get("unique"):
                uniq |= {c for c in (ix.get("column_names") or []) if c}
        unique_str = [c for c in uniq if c and c not in (pk, email, pw)
                      and any(t in coltype.get(c, "") for t in ("CHAR", "TEXT", "STRING"))]
        candidates.append((score, table, {"email": email, "pw": pw, "pk": pk,
                                          "admin": admin, "active": active,
                                          "unique": unique_str}))
    if not candidates:
        raise _ProvisionError("could not locate an authenticatable user table")
    candidates.sort(key=lambda c: c[0], reverse=True)
    _, table, roles = candidates[0]
    return table, roles


def _provision_via_db(profile: AppProfile, req: ProvisionRequest,
                      res: ProvisionResult) -> ProvisionResult:
    from sqlalchemy import inspect, text

    eng = _engine(req.db_url)
    insp = inspect(eng)
    table, roles = _find_user_table(insp, req.user_table)
    all_cols = [c["name"] for c in insp.get_columns(table)]
    res.notes.append(f"provisioning into '{table}' (email={roles['email']}, "
                     f"pw={roles['pw']}, admin_flag={roles['admin']})")

    with eng.begin() as conn:
        # Idempotent re-provisioning: clear any users a prior run left behind.
        try:
            conn.execute(text(f'DELETE FROM "{table}" WHERE "{roles["email"]}" LIKE :pfx'),
                         {"pfx": "heimdall.%"})
        except Exception:  # noqa: BLE001 — FK constraints may block deletes; ignore
            pass

        # Pick a REPRESENTATIVE template, not just the first row: cloning a
        # random non-admin can land on an atypical account (e.g. an 'external'
        # user the app blocks from most routes), which silently skews auth
        # results. We clone the row whose email domain is the most common among
        # non-admins — the "typical" user — so provisioning is deterministic.
        flag = roles["admin"]
        email_col = roles["email"]

        def _modal_domain(want_admin: bool) -> str | None:
            where = f' WHERE "{flag}" = {1 if want_admin else 0}' if flag else ""
            rows = conn.execute(
                text(f'SELECT "{email_col}" FROM "{table}"{where}')).scalars().all()
            doms: dict[str, int] = {}
            for e in rows:
                d = str(e).split("@")[-1] if e and "@" in str(e) else ""
                if d:
                    doms[d] = doms.get(d, 0) + 1
            return max(doms, key=doms.get) if doms else None

        def template(want_admin: bool):
            where = f' WHERE "{flag}" = {1 if want_admin else 0}' if flag else ""
            dom = _modal_domain(want_admin)
            row = None
            if dom:
                row = conn.execute(
                    text(f'SELECT * FROM "{table}"{where}'
                         f'{" AND" if where else " WHERE"} "{email_col}" LIKE :d LIMIT 1'),
                    {"d": f"%@{dom}"}).mappings().first()
            if row is None:
                row = conn.execute(
                    text(f'SELECT * FROM "{table}"{where} LIMIT 1')).mappings().first()
            if row is None:
                row = conn.execute(text(f'SELECT * FROM "{table}" LIMIT 1')).mappings().first()
            if row is None:
                raise _ProvisionError(f"'{table}' has no template row to clone")
            return dict(row)

        specs = [("prov_user", "user", False)] * req.low_priv + \
                [("prov_admin", "admin", True)] * req.admins
        inserted = []  # (label, role, ident, user_id) — logged in AFTER commit
        for idx, (base_label, role, want_admin) in enumerate(specs):
            tmpl = template(want_admin)
            domain = req.email_domain or (str(tmpl.get(roles["email"], "")).split("@")[-1]
                                          or "example.com")
            ident = f"heimdall.{base_label}{idx}@{domain}"
            new = dict(tmpl)
            new[roles["pk"]] = str(uuid.uuid4())
            new[roles["email"]] = ident
            new[roles["pw"]] = _bcrypt_hash(req.password)
            # Give every UNIQUE string column (username/login/…) a distinct value.
            for uc in roles.get("unique", []):
                if uc in new:
                    new[uc] = f"heimdall_{base_label}{idx}"[:60]
            # Python bools work for both Postgres BOOLEAN and SQLite; ints don't
            # (Postgres rejects integer-for-boolean).
            if roles["admin"]:
                new[roles["admin"]] = bool(want_admin)
            if roles["active"]:
                new[roles["active"]] = True
            cols = [c for c in all_cols if c in new]
            conn.execute(
                text(f'INSERT INTO "{table}" ({",".join(chr(34)+c+chr(34) for c in cols)}) '
                     f'VALUES ({",".join(":"+c for c in cols)})'),
                {c: new[c] for c in cols},
            )
            inserted.append((f"{base_label}{idx}", role, ident, str(new[roles["pk"]])))

    # Transaction committed — the running app can now see the rows; log them in.
    for label, role, ident, uid in inserted:
        p = _login_principal(profile, ident, req.password, label=label, role=role, user_id=uid)
        if p and p.token:
            res.principals.append(p)
    res.notes.append(f"inserted {len(inserted)} user(s); {len(res.principals)} logged in")
    return res


def _login_principal(profile: AppProfile, ident: str, password: str, *,
                     label: str, role: str, user_id: str) -> Principal | None:
    http = HttpClient(profile.base_url, scheme=profile.auth.header_scheme,
                      auth_kind=profile.auth.auth_kind,
                      credential_name=profile.auth.credential_name)
    tok = login(http, profile, ident, password)
    p = Principal(label=label, role=role, email=ident, username=ident.split("@")[0],
                  password=password, token=tok, user_id=user_id)
    if tok and not profile.auth.jwt_alg:
        auth_detect.enrich_with_token(profile.auth, tok)
    return p


def _provision_via_command(req: ProvisionRequest, res: ProvisionResult) -> ProvisionResult:
    """Escape hatch: run an app-specific command that prints a JSON list of
    principals (``[{"label","role","identifier","token"[,"user_id"]}]`` on the
    last stdout line) — for apps whose seeding is best done with their own tools."""
    import json
    import subprocess
    try:
        out = subprocess.run(req.command, shell=True, cwd=req.command_cwd,
                             capture_output=True, text=True, timeout=180)
    except Exception as exc:  # noqa: BLE001
        res.notes.append(f"provision command failed: {exc}")
        return res
    try:
        items = json.loads(out.stdout.strip().splitlines()[-1])
    except Exception as exc:  # noqa: BLE001
        res.notes.append(f"provision command output not JSON: {exc}; stderr={out.stderr[:200]}")
        return res
    for it in items:
        res.principals.append(Principal(
            label=it["label"], role=it.get("role", "user"),
            email=it.get("identifier"), username=it.get("identifier"),
            token=it.get("token"), user_id=it.get("user_id"), supplied=True))
    res.notes.append(f"provision command produced {len(res.principals)} principal(s)")
    return res
