"""Vulnerable-by-design FastAPI app — a demo target for Heimdall.

⚠️  DO NOT DEPLOY. Every "vuln:" comment below is an *intentional* flaw planted
    so `heimdall --url http://127.0.0.1:8000 --source examples/vulnerable_app`
    has something to find. It is a teaching target, like DVWA or Juice Shop.

Run:
    pip install fastapi uvicorn pyjwt          # or: pip install -e '.[demo]'
    uvicorn examples.vulnerable_app.main:app --port 8000

Seeded accounts:  admin / admin123   ·   alice / alice123   ·   bob / bob123
"""

from __future__ import annotations

import hashlib
import sqlite3
import urllib.request
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from .config import ALGO, SECRET_KEY, SEED_USERS

DB = Path(__file__).with_name("demo.sqlite")
oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)
app = FastAPI(title="Vulnerable Demo API", version="0.0.1")

# vuln (A05): reflect any Origin *and* allow credentials — a total CORS bypass.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


# --------------------------------------------------------------------------- db
def _hash(pw: str) -> str:
    # vuln (A02): unsalted SHA-256 for password storage.
    return hashlib.sha256(pw.encode()).hexdigest()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# (username, email, plaintext-password, is_admin, ssn, balance)
_SEED_ROWS = {
    "admin": ("admin@demo.test", "admin123", 1, "111-11-1111", 1000),
    "alice": ("alice@demo.test", "alice123", 0, "222-22-2222", 100),
    "bob": ("bob@demo.test", "bob123", 0, "333-33-3333", 100),
}


def _insert_seed_user(conn: sqlite3.Connection, username: str) -> None:
    email, pw, is_admin, ssn, balance = _SEED_ROWS[username]
    conn.execute(
        "INSERT OR IGNORE INTO users (username,email,password_hash,is_admin,ssn,balance)"
        " VALUES (?,?,?,?,?,?)",
        (username, email, _hash(pw), is_admin, ssn, balance),
    )


def _seed() -> None:
    conn = _db()
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS users ("
        " id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT,"
        " password_hash TEXT, is_admin INTEGER DEFAULT 0, ssn TEXT, balance INTEGER DEFAULT 100);"
        "CREATE TABLE IF NOT EXISTS notes ("
        " id INTEGER PRIMARY KEY, owner TEXT, body TEXT);"
    )
    for username in SEED_USERS:
        _insert_seed_user(conn, username)
    conn.executemany(
        "INSERT OR IGNORE INTO notes (id, owner, body) VALUES (?,?,?)",
        [(1, "alice", "alice's private note"), (2, "bob", "bob's private note")],
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def _startup() -> None:
    _seed()


# ------------------------------------------------------------------------ auth
def _current(token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    try:
        claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
    except jwt.PyJWTError:
        return None
    sub = claims.get("sub")
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (sub,)).fetchone()
    # Self-heal: Heimdall's own destructive delete-BOLA probe removes users
    # mid-run. Because the JWT itself carries the identity, a holder of a valid
    # token can rebuild its own row — seed users from their canonical fixture,
    # anyone else (a self-registered attacker, a provisioned user) from the token
    # claims. So a deleted principal reappears only when *it* next presents its
    # token: cross-user probes still see the victim as gone (write-BOLA stays
    # observable) while every assessor principal keeps working across modules.
    if row is None and sub:
        if sub in SEED_USERS:
            _insert_seed_user(conn, sub)
        else:
            conn.execute(
                "INSERT OR IGNORE INTO users (username,email,password_hash,is_admin,ssn)"
                " VALUES (?,?,?,?,?)",
                (sub, f"{sub}@demo.test", "", 1 if claims.get("is_admin") else 0, "000-00-0000"),
            )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE username=?", (sub,)).fetchone()
    conn.close()
    return row


def require_user(token: str | None = Depends(oauth2)) -> sqlite3.Row:
    user = _current(token)
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


class Register(BaseModel):
    username: str
    email: str
    password: str
    is_admin: bool | None = None          # vuln (mass-assignment): client-settable


class Login(BaseModel):
    username: str
    password: str


@app.post("/auth/register")
def register(body: Register):
    conn = _db()
    # vuln (A07): no password strength check — "1" is accepted.
    # vuln (mass-assignment): is_admin taken straight from the request body.
    try:
        cur = conn.execute(
            "INSERT INTO users (username,email,password_hash,is_admin,ssn)"
            " VALUES (?,?,?,?,?)",
            (body.username, body.email, _hash(body.password),
             1 if body.is_admin else 0, "000-00-0000"),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    finally:
        conn.close()
    # vuln (data-exposure): echoes password_hash, ssn, is_admin back to the client.
    return dict(row)


@app.post("/auth/login")
def login(body: Login):
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    conn.close()
    # vuln (A07): distinct messages leak which usernames exist (enumeration).
    if row is None:
        raise HTTPException(status_code=404, detail="no such user")
    if row["password_hash"] != _hash(body.password):
        raise HTTPException(status_code=401, detail="wrong password")
    # vuln (A07): no rate limiting — brute force is unthrottled.
    token = jwt.encode(
        {"sub": row["username"], "is_admin": bool(row["is_admin"])}, SECRET_KEY, algorithm=ALGO)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me")
def me(user: sqlite3.Row = Depends(require_user)):
    # vuln (data-exposure): returns the caller's own hash + ssn.
    return dict(user)


# ------------------------------------------------------------------------ users
@app.get("/users")
def list_users(request: Request, user: sqlite3.Row = Depends(require_user)):
    conn = _db()
    # vuln (resource-consumption): no pagination, returns every row.
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    # vuln (data-exposure): PII (email, ssn) + password_hash for all users.
    return [dict(r) for r in rows]


@app.get("/users/{user_id}")
def get_user(user_id: int, user: sqlite3.Row = Depends(require_user)):
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    # vuln (A01 BOLA/IDOR): any authenticated user reads any other user's record.
    return dict(row)


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, user: sqlite3.Row = Depends(require_user)):
    conn = _db()
    # vuln (A01 write-BOLA): no ownership/role check on a destructive action.
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()


@app.get("/admin/users")
def admin_users(user: sqlite3.Row = Depends(require_user)):
    # vuln (A01 BFLA): an "admin" route that never checks is_admin.
    conn = _db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# -------------------------------------------------------------------- injection
@app.get("/search")
def search(q: str, user: sqlite3.Row = Depends(require_user)):
    conn = _db()
    # vuln (A03 SQLi): user input concatenated straight into the query.
    sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'"
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.Error as exc:
        conn.close()
        # vuln (A05): raw DB error echoed to the client.
        return JSONResponse(status_code=500, content={"error": str(exc), "sql": sql})
    conn.close()
    return [dict(r) for r in rows]


@app.get("/greet", response_class=HTMLResponse)
def greet(name: str = "world"):
    # vuln (A03 reflected XSS): name rendered into HTML without escaping.
    return f"<html><body><h1>Hello {name}</h1></body></html>"


# --------------------------------------------------------- ssrf / redirect / host
@app.get("/fetch")
def fetch(url: str, user: sqlite3.Row = Depends(require_user)):
    # vuln (A10 SSRF): server fetches an arbitrary client-supplied URL. Only the
    # http(s) scheme is honoured and errors are handled — so a garbage or non-URL
    # value returns a clean 400 instead of crashing the worker (which made runs
    # non-deterministic). The SSRF itself is intact: any internal http(s) target
    # is fetched server-side.
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
            return {"status": resp.status, "body": resp.read(2048).decode("utf-8", "replace")}
    except Exception as exc:  # noqa: BLE001 — demo: surface the fetch error, don't crash
        raise HTTPException(status_code=502, detail=f"fetch failed: {exc}") from None


@app.get("/go")
def go(next: str):
    # vuln (open-redirect): redirects to an unvalidated destination.
    return RedirectResponse(next)


@app.post("/auth/forgot-password")
def forgot(body: Login, request: Request, host: str = Header(default="")):
    # vuln (host-header): the reset link trusts the Host header for its origin,
    # so an attacker-controlled Host poisons the link sent to the victim.
    link = f"https://{host}/reset?user={body.username}&token=abc123"
    return {"message": "reset link sent", "reset_link": link}


# --------------------------------------------------------------- business / race
@app.post("/wallet/redeem")
def redeem(user: sqlite3.Row = Depends(require_user)):
    conn = _db()
    # vuln (race/TOCTOU): read-modify-write with no locking or atomic UPDATE, so
    # concurrent redeems each see the same balance and all succeed (double-spend).
    bal = conn.execute("SELECT balance FROM users WHERE id=?", (user["id"],)).fetchone()[0]
    if bal < 100:
        conn.close()
        raise HTTPException(status_code=400, detail="insufficient balance")
    new_bal = bal - 100
    conn.execute("UPDATE users SET balance=? WHERE id=?", (new_bal, user["id"]))
    conn.commit()
    conn.close()
    return {"redeemed": True, "balance": new_bal}


# ---------------------------------------------------------- intentionally-secure
# These endpoints are correct — Heimdall should report them TESTED-SAFE, showing
# it does not just flag everything.
@app.get("/me/notes")
def my_notes(user: sqlite3.Row = Depends(require_user)):
    conn = _db()
    # safe: strictly scoped to the caller, parameterized query.
    rows = conn.execute("SELECT * FROM notes WHERE owner=?", (user["username"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/health")
def health():
    # safe: public by design, no data.
    return {"status": "ok"}
