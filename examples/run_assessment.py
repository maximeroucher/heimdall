"""Programmatic example: assess a FastAPI app from Python.

    python examples/run_assessment.py

Edit the values below to point at your own app (running on loopback), then run.
This mirrors `heimdall --config examples/example.toml` but from code, so you can
post-process `result` however you like.
"""

import heimdall

result = heimdall.assess(
    base_url="http://127.0.0.1:8000",
    name="Example API",
    # Optional white-box source tree — unlocks JWT-secret recovery, the `a06`
    # component audit and the `sast` source-sink module. Omit for black-box.
    source_path="/path/to/your-app",
    # Privileged accounts Heimdall can't self-register: (label, role, id, password).
    credentials=[
        ("admin", "admin", "admin@example.com", "change-me"),
        ("member", "user", "member@example.com", "change-me"),
    ],
    # safe=True would skip every destructive/mutating probe.
)

print(result.counts())          # {'CRITICAL': 1, 'HIGH': 3, 'SAFE': 12, ...}
for f in result.issues:         # real findings, worst-first
    print(f"{f.severity:<8} {f.owasp}  {f.title}")

md_path = result.report_paths[1]
print(f"\nFull report: {md_path}")
