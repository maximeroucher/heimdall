# Examples

Two ways to run Heimdall against a target:

| File | What it shows |
|---|---|
| [`example.toml`](example.toml) | A config file for the CLI: `heimdall --config examples/example.toml` |
| [`run_assessment.py`](run_assessment.py) | The equivalent from Python via `heimdall.assess(...)` |

Both point at `http://127.0.0.1:8000` with placeholder credentials — edit them
for your own app. Copy `example.toml` to `example.local.toml` before adding real
credentials; `*.local.toml` is git-ignored so nothing sensitive gets committed.

Only ever run against apps you own or are explicitly authorized to test. Heimdall
refuses any non-loopback target unless you pass `--i-have-authorization`.
