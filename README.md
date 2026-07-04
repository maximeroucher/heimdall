# Heimdall

**A self-discovering OWASP Top-10 pentest library for FastAPI applications.**

> Heimdall is the watchman of the Norse gods — he sees everything that approaches.
> Point Heimdall at a running FastAPI app and it *sees the app*: it learns the
> routes, the auth shape, and (optionally) the signing secrets, then runs the
> OWASP Top-10 exploit modules against the live target and writes a report.

It grew out of a hand-written pentest of one app and was generalized so the same
methodology runs against **any** FastAPI service with near-zero per-app wiring.

---

## Why it's generic

Most pentest scripts hard-code paths (`/core/auth/login`), credentials, and the
victim's data model. Heimdall doesn't. It **discovers** them:

| Concern | How Heimdall learns it |
|---|---|
| Every route, method, required-auth, params, body schema | `GET /openapi.json` (every FastAPI app serves it) |
| Login shape (JSON vs OAuth2 form vs `simple_token`) | Heuristic scoring over the OpenAPI operations |
| Register / "current user" endpoints | Same |
| Auth transport — bearer token **or** cookie-session | `securitySchemes` + the live login response (302/204 + `Set-Cookie` → cookie jar; `Authorization` scheme → token) |
| JWT algorithm & claim shape | Decodes a real token minted through the login flow |
| Candidate signing secrets, dependency stack | Optional white-box scan of the source tree (`--source`) |

Modules then operate off that discovered map — so a check written once ("secured
routes must reject anonymous callers") runs against any FastAPI app
unchanged. Auth-shape detection means the CSRF and session modules light up on a
cookie-session app and stay quiet on a token API, with no per-app configuration.

## Install

```bash
uv pip install -e '.[full]'      # full = JWT forging + pip-audit + TOML on 3.10
# or minimal: uv pip install -e .
```

## Use

### CLI

```bash
# Black-box, discovery only (no attacks) — a safe first look:
heimdall --url http://127.0.0.1:8000 --discover-only

# Full assessment, white-box (source tree enables JWT-secret + component checks):
heimdall --url http://127.0.0.1:8000 \
         --source /path/to/YourApp \
         --cred admin:admin:admin@you.io:hunter2 \
         --cred member:user:member@you.io:pw

# Or from a config file:
heimdall --config examples/example.toml

# Non-destructive pass, or scope to specific modules:
heimdall --url http://127.0.0.1:8000 --safe
heimdall --url http://127.0.0.1:8000 --only a01,a02
heimdall --url http://127.0.0.1:8000 --skip race,cmdi,xxe
heimdall --list-modules
```

#### Full flag reference

| Flag | Purpose |
|---|---|
| `--url URL` | Target base URL (required unless `--config` supplies it). |
| `--source PATH` | Target source tree — enables white-box checks (JWT-secret recovery, `a06` components, `sast`). |
| `--name NAME` | Friendly app name for the report. |
| `--config FILE` | TOML/JSON target config (CLI flags override its fields). |
| `--cred label:role:identifier:password` | A login credential; repeatable. `role` is free-form (`admin`, `user`, …) and drives BFLA/BOLA pairing. |
| `--launch CMD` / `--launch-cwd DIR` | Boot the target with a shell command first (and its working dir), then tear it down after. |
| `--spawn-db` / `--spawn-db-env VAR` | Spin up a throwaway DB matching the target's engine (Docker Postgres/MySQL/Mongo, or a SQLite file) and hand it to the target via `VAR` (default `SQLITE_DB`); torn down after. |
| `--db-url URL` | An existing throwaway SQLAlchemy URL to provision into (use `postgresql+psycopg2://…`). |
| `--provision N` / `--provision-admins N` | Insert N low-privilege (and N admin) test users straight into the DB, so BOLA/IDOR/BFLA checks have real cross-tenant subjects even when self-registration is closed. |
| `--no-mint` | Don't mint API-scoped JWTs even if the signing secret is recovered. |
| `--no-attacker` | Don't self-register a throwaway low-priv attacker account. |
| `--safe` | Skip every mutating/destructive probe. |
| `--only KEYS` / `--skip KEYS` | Comma-separated module keys to include / exclude. |
| `--fail-on LEVEL` | CI gate severity (`none,info,low,medium,high,critical`; default `high`). |
| `--baseline findings.json` | Suppress already-known findings; gate only on new ones. |
| `--discover-only` | Print the discovered profile (routes, auth, secrets) and exit — no attacks. |
| `--list-modules` | List registered modules and exit. |
| `--i-have-authorization` | Permit a non-loopback target (authorized use only). |
| `--out DIR` / `--no-color` | Report output dir (default `./heimdall-report`) / disable ANSI colour. |

#### Provisioning & throwaway targets

For a deep run against an app whose sign-up is closed (or to drive access-control
checks across *many* distinct owners), let Heimdall build the world:

```bash
# Boot the app onto a throwaway DB, seed real principals, then attack — all disposable:
heimdall --url http://127.0.0.1:8000 \
         --launch 'uvicorn app.main:app --port 8000' --launch-cwd /path/to/App \
         --spawn-db \
         --provision 3 --provision-admins 1
```

`--provision` inserts distinct users (hashing passwords the way the app's own
model expects) and logs each in through the real login flow, giving the `a01`
BOLA/IDOR/BFLA probes genuine cross-user subjects. Combined with `--spawn-db` /
`--launch`, a whole assessment — server, database, users — is created and torn
down around a single command.

### Library

```python
import heimdall

result = heimdall.assess(
    base_url="http://127.0.0.1:8000",
    source_path="/path/to/YourApp",              # optional white-box
    credentials=[("admin", "admin", "admin@you.io", "hunter2")],  # label,role,id,pw
    safe=False,                                  # True → skip destructive probes
    only={"a01", "a02"},                         # or skip={"race", "cmdi"}
)
print(result.counts())            # {'CRITICAL': 1, 'HIGH': 3, 'SAFE': 9, ...}
print(result.report_paths)        # (findings.json, REPORT.md, REPORT.html, findings.sarif)
```

Drive discovery alone:

```python
profile = heimdall.discover("http://127.0.0.1:8000", source_path="…")
print(heimdall.summarize(profile))
```

## Modules

26 detectors, grouped by OWASP category. Run `heimdall --list-modules` for the
live registry. Modules marked **⚡** are *destructive* (they mutate state) and are
skipped under `--safe`.

| Key | Title | What it does |
|---|---|---|
| **A01 — Broken Access Control** | | |
| `a01` | Access Control / IDOR | Unauth access to secured routes; BFLA on admin routes; BOLA/IDOR on object-by-id routes across owners |
| `csrf` | Cross-Site Request Forgery | On cookie-session apps: session-cookie `SameSite` + anti-CSRF-token enforcement (auto-skipped for token auth) |
| `data-exposure` | Excessive Data Exposure | Secrets/PII/other users' tokens in responses (own-token & public-metadata aware) |
| `mass-assignment` ⚡ | Mass Assignment | Over-posting privileged fields (`is_admin`, `role`) on create/update, with a determinism gate |
| `oidc` | OAuth / OIDC Flow | `state`/PKCE/`redirect_uri` handling on discovered OAuth flows |
| `open-redirect` | Open Redirect | Redirect params that navigate off-host (parsed like a browser, not by substring) |
| **A02 — Cryptographic Failures** | | |
| `a02` | JWT forging | `alg:none` forgery + weak-HS256-secret crack, *proven by live acceptance*; token-in-query leak |
| **A03 — Injection** | | |
| `a03` | Injection | SQLi (error/boolean, reproducibility-gated) + reflected-XSS + SSTI + traversal + operator injection |
| `sqli-blind` ⚡ | Blind SQLi | Time-based blind SQL injection |
| `cmdi` ⚡ | OS Command Injection | Time-based OS command injection |
| `xxe` ⚡ | XML External Entity | XXE file disclosure (structural passwd-line match) on XML-accepting routes |
| `sast` | SAST → DAST chaining | Source-sink scan whose findings are re-probed live against the running app |
| **A04 — Insecure Design** | | |
| `business-logic` ⚡ | Numeric Abuse | Negative/overflow quantities & price/amount tampering |
| `race` ⚡ | Race / TOCTOU | Concurrent double-spend; flags only *divergent* (cumulative) races, not idempotent ones |
| `workflow` ⚡ | Multi-step Replay | Replaying a step for a double effect |
| `resource-consumption` | Resource Consumption | Unbounded pagination / payload size / missing rate limits |
| **A05 — Security Misconfiguration** | | |
| `a05` | Misconfiguration | CORS reflection, missing security headers, docs exposure, stack-trace/debug leaks |
| `host-header` | Host Header Attacks | Host/`X-Forwarded-Host` poisoning reflected into URLs |
| `improper-inventory` | Sensitive Paths | Exposed `.env`/config/backup/VCS & undocumented admin surfaces |
| `graphql` | GraphQL Exposure | Introspection, suggestions, unauth queries |
| `websocket` | WebSocket Security | Origin/auth enforcement on discovered WS endpoints |
| `file-upload` ⚡ | Unrestricted Upload | Dangerous file types accepted on upload sinks |
| **A06 — Vulnerable Components** | | |
| `a06` | Outdated Components | `pip-audit` + heuristic version checks (needs `--source`) |
| **A07 — Authentication Failures** | | |
| `a07` | Auth Failures | Login rate-limit + XFF bypass, user enumeration, weak passwords, lockout (429/423) vs OAuth-token endpoints |
| `session` | Session Lifecycle | Token/session expiry, logout invalidation, rotation |
| **A10 — SSRF** | | |
| `a10` | SSRF | URL-accepting sink discovery + internal-target / cloud-metadata probes |

Each module also emits **TESTED-SAFE** findings so the report distinguishes
*verified-safe* from *untested*.

## Output

Each run writes to `heimdall-report/`:
- `REPORT.md` — executive summary, **attack chains**, per-finding OWASP mapping,
  indicative CVSS, evidence/PoC, reproduction, references, tools.
- `REPORT.html` — the same, standalone + styled (shareable).
- `findings.json` — machine-readable.
- `findings.sarif` — SARIF 2.1.0 for GitHub/GitLab/Azure code-scanning
  (real findings as `kind:fail`, TESTED-SAFE as `kind:pass`).

## CI integration

```bash
# fail the build on any finding at/above a threshold (default: high)
heimdall --url http://127.0.0.1:8000 --source . --fail-on high

# regression gate: only fail on findings NOT already in a baseline report
heimdall --url http://127.0.0.1:8000 --baseline known-findings.json --fail-on medium
```

`--fail-on {none,info,low,medium,high,critical}` sets the exit-code gate;
`--baseline <findings.json>` suppresses already-known/accepted findings so CI
only breaks on *new* ones. Upload `findings.sarif` with
`github/codeql-action/upload-sarif` to surface results in the Security tab.

## Safety & scope

- **Guardrail:** Heimdall refuses any non-loopback target unless you pass
  `--i-have-authorization`.
- `--safe` skips every mutating/destructive probe.
- Reports may contain secrets and target internals — the repo `.gitignore`
  excludes them; keep them out of version control.

### ⚖️ Authorized use only

This is a security-testing tool. **Use it only against systems you own or for
which you have prior, explicit, written authorization to test.** Unauthorized
scanning or exploitation of systems you do not own is illegal in most
jurisdictions (e.g. the US Computer Fraud and Abuse Act, EU Directive 2013/40/EU,
the UK Computer Misuse Act 1990, and equivalents). By using this software you
confirm you have the necessary authorization for every target and accept sole
responsibility for your use of it; the authors accept no liability for misuse.
See the [LICENSE](LICENSE) for the full disclaimer.

## How it fits together

```
heimdall/
  discovery/   openapi → RouteMap · auth detection (token/cookie) · JWKS · source secret scan → AppProfile
  bootstrap/   launch target · spawn throwaway DB · provision users · mint principals via the real login flow
  modules/     26 detectors, each reading the AppProfile — no hard-coded paths
  core/        Context, Finding, report renderer (MD/HTML/SARIF), attack-chain builder, loopback guardrail
  runner.py    launch → discover → bootstrap → modules → report
```

## Status

Alpha. The discovery layer targets FastAPI/OpenAPI 3.x; the exploit modules are
black-box-first and conservative about false positives (unconfirmed SSRF sinks,
heuristic enumeration, etc. are labelled as needing manual/OAST confirmation).
A 60+-case test suite (`pytest`) pins each module's precision — every
false-positive fix ships with a false-negative control and a regression test.
