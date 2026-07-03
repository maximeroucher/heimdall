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
| JWT algorithm & claim shape | Decodes a real token minted through the login flow |
| Candidate signing secrets, dependency stack | Optional white-box scan of the source tree (`--source`) |

Modules then operate off that discovered map — so a check written once ("secured
routes must reject anonymous callers") runs against the app, the app, or your app
unchanged.

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
heimdall --list-modules
```

### Library

```python
import heimdall

result = heimdall.assess(
    base_url="http://127.0.0.1:8000",
    source_path="/path/to/YourApp",
    credentials=[("admin", "admin", "admin@you.io", "hunter2")],
)
print(result.counts())            # {'CRITICAL': 1, 'HIGH': 3, 'SAFE': 9, ...}
print(result.report_paths)        # (findings.json, REPORT.md)
```

Drive discovery alone:

```python
profile = heimdall.discover("http://127.0.0.1:8000", source_path="…")
print(heimdall.summarize(profile))
```

## Modules

| Key | OWASP | What it does |
|---|---|---|
| `a01` | Broken Access Control | Unauth access to secured routes; BFLA on admin routes; IDOR on object-by-id routes |
| `a02` | Cryptographic Failures | JWT `alg:none` forgery + weak-HS256-secret crack, proven by live acceptance; token-in-query |
| `a03` | Injection | SQLi sweep (error/500-based) + reflected-XSS + operator-injection probes |
| `a05` | Security Misconfiguration | CORS reflection, missing security headers, docs exposure, stack-trace/debug leaks |
| `a06` | Vulnerable Components | `pip-audit` + heuristic version checks (needs `--source`) |
| `a07` | Auth Failures | Login rate-limit + XFF bypass, user enumeration, register mass-assignment, weak passwords |
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
  `--i-have-authorization`. Only ever test systems you own or are authorized to.
- `--safe` skips every mutating/destructive probe.
- Reports may contain secrets and target internals — the repo `.gitignore`
  excludes them; keep them out of version control.

## How it fits together

```
heimdall/
  discovery/   openapi → RouteMap · auth detection · source secret scan → AppProfile
  bootstrap/   launch target (optional) · mint principals via the real login flow
  modules/     a01…a10, each reading the AppProfile — no hard-coded paths
  core/        Context, Finding, report renderer, loopback guardrail, data model
  runner.py    launch → discover → bootstrap → modules → report
```

## Status

Alpha. The discovery layer targets FastAPI/OpenAPI 3.x; the exploit modules are
black-box-first and conservative about false positives (unconfirmed SSRF sinks,
heuristic enumeration, etc. are labelled as needing manual/OAST confirmation).
