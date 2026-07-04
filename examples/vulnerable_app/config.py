"""App configuration for the vulnerable demo.

vuln (A02): a hard-coded, low-entropy JWT signing secret committed to source.
Heimdall's white-box source scan (`--source`) recovers it from this config file
and forges a valid — even admin — token; the same secret is weak enough to be a
black-box crack candidate too.
"""

SECRET_KEY = "demo-secret-123"
ALGO = "HS256"

# Accounts seeded on startup. Kept here so the app can self-heal them (see
# main.py): Heimdall's own destructive probes delete users mid-run, and without
# healing the seeded principals it authenticated as would vanish.
SEED_USERS = ("admin", "alice", "bob")
