# Vulnerable demo app

A deliberately-insecure FastAPI app used to demonstrate Heimdall. It is riddled
with planted flaws (every one marked `# vuln (...)` in [`main.py`](main.py)), plus
a couple of correct endpoints so you can see Heimdall report **TESTED-SAFE** too.

> ⚠️ **Never deploy this.** It is a teaching target, like DVWA or OWASP Juice
> Shop. Run it only on loopback.

## Run it, then scan it

```bash
pip install -e '.[demo]'          # fastapi + uvicorn + pyjwt
uvicorn examples.vulnerable_app.main:app --host 127.0.0.1 --port 8099

# in another shell — white-box so Heimdall also recovers the hard-coded secret.
# Three creds give it two low-priv victims (cross-user BOLA); --no-attacker keeps
# it to the stable seed accounts.
heimdall --url http://127.0.0.1:8099 \
         --source examples/vulnerable_app \
         --cred admin:admin:admin:admin123 \
         --cred alice:user:alice:alice123 \
         --cred bob:user:bob:bob123 \
         --no-attacker
```

Seeded accounts: `admin/admin123`, `alice/alice123`, `bob/bob123`.

A run reports **1 CRITICAL + 11 HIGH** and detects **every** planted flaw in the
table below (verified stable across repeated runs), plus TESTED-SAFE on the
correct endpoints.

> **Pick a free port.** If something already listens on your chosen port, two
> servers can end up bound to it and requests get split between them — results go
> haywire. `8099` is used above to avoid the common `8000`.
>
> The demo mutates state as it's probed, but detection is stable run-to-run: seed
> principals self-heal so the assessor's accounts survive the delete-BOLA probe,
> and the coupon double-spend is exposed by concurrency (not a one-shot balance),
> so the race finding fires reliably. Restart the app for a pristine DB.

## What's planted (and which module catches it)

| Endpoint | Flaw | Module / OWASP |
|---|---|---|
| `SECRET_KEY` in source | Hard-coded low-entropy HS256 secret → forge an admin token | `a02` · A02 |
| `GET /users/{id}` | Any user reads any other user's record | `a01` (BOLA/IDOR) · A01 |
| `DELETE /users/{id}` | Any user deletes any user (no ownership/role check) | `a01` (write-BOLA) · A01 |
| `GET /admin/users` | "Admin" route never checks `is_admin` | `a01` (BFLA) · A01 |
| `POST /auth/register` | `is_admin` is client-settable | `mass-assignment` · A01 |
| `GET /auth/me`, `/users` | Responses leak `password_hash`, `ssn`, PII | `data-exposure` · A01 |
| `GET /search?q=` | Raw string-built SQL | `a03`, `sqli-blind` · A03 |
| `GET /greet?name=` | Unescaped HTML reflection | `a03` (XSS) · A03 |
| `GET /fetch?url=` | Server fetches arbitrary URL | `a10` (SSRF) · A10 |
| `GET /go?next=` | Unvalidated redirect | `open-redirect` · A01 |
| `POST /auth/forgot-password` | Reset link trusts the `Host` header | `host-header` · A05 |
| `POST /auth/login` | No rate limit; user enumeration; weak passwords | `a07` · A07 |
| `GET /feed?limit=` | Page size has no server-side cap (memory/CPU exhaustion) | `resource-consumption` · A04 |
| `POST /wallet/redeem` | Non-atomic read-modify-write balance | `race` · A04 |
| CORS `*` + credentials, raw errors, `/docs` | Misconfiguration | `a05` · A05 |
| `GET /me/notes`, `/health` | **Correct** — expect TESTED-SAFE | — |
