"""Orchestrate a full run: (launch) → discover → bootstrap → modules → report."""

from __future__ import annotations

import importlib
import os
import pkgutil
import traceback
from datetime import datetime

from .bootstrap import server
from .config import TargetConfig
from .core.context import Context
from .core.findings import write_reports
from .core.guardrail import assert_target_allowed
from .core.model import AppProfile
from .discovery import build as discovery
from .discovery import summarize


def _import_all_modules() -> None:
    """Import every file in heimdall.modules so @module registers them."""
    from . import modules as pkg
    for m in pkgutil.iter_modules(pkg.__path__):
        if m.name != "base":
            importlib.import_module(f"{pkg.__name__}.{m.name}")


class RunResult:
    def __init__(self, profile: AppProfile, findings, report_paths):
        self.profile = profile
        self.findings = findings
        self.report_paths = report_paths

    @property
    def issues(self):
        return [f for f in self.findings if f.severity != "SAFE"]

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


def run(
    config: TargetConfig,
    *,
    out_dir: str | None = None,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    safe: bool = False,
    verbose: bool = True,
) -> RunResult:
    from .bootstrap.principals import bootstrap as bootstrap_principals

    assert_target_allowed(config.base_url, config.authorized)

    proc = None
    if config.launch:
        print(f"[*] launching target: {config.launch}")
        proc = server.launch(config.launch, cwd=config.launch_cwd, env=config.launch_env)
    try:
        if not server.wait_for_server(config.base_url, timeout=60):
            raise SystemExit(f"[!] target {config.base_url} never became reachable")

        print("[*] discovering application surface…")
        profile = discovery.discover(
            config.base_url, source_path=config.source_path, app_name=config.name)
        print(summarize(profile))

        print("\n[*] bootstrapping principals…")
        principals = bootstrap_principals(
            profile, config.credentials, make_attacker=config.make_attacker)
        authed = [k for k, p in principals.items() if p.authed]
        print(f"[*] authenticated principals: {authed or 'none'}")

        ctx = Context(profile, safe=safe, verbose=verbose)

        _import_all_modules()
        from .modules.base import ordered
        specs = ordered()

        print(f"\n[*] running {len(specs)} module(s) "
              f"({'SAFE' if safe else 'FULL'} mode)\n")
        for spec in specs:
            if only and spec.key not in only:
                continue
            if skip and spec.key in skip:
                continue
            if spec.destructive and safe:
                print(f"[-] {spec.key}: {spec.name} (skipped — destructive, safe mode)")
                continue
            print(f"[+] {spec.key}: {spec.name}")
            ctx._current_module = spec.key
            try:
                spec.fn(ctx)
            except Exception:  # noqa: BLE001 — a crashing module must not abort the run
                print(f"[!] module {spec.key} crashed:")
                traceback.print_exc()
                ctx.note(f"module {spec.key} crashed mid-run (partial results)")

        findings = ctx.findings()
        out_dir = out_dir or os.path.join(os.getcwd(), "heimdall-report")
        meta = {
            "app_name": profile.app_name,
            "base_url": profile.base_url,
            "framework": profile.framework,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "safe": safe,
            "route_count": len(profile.routes),
            "principals": authed,
            "notes": profile.notes,
        }
        paths = write_reports(findings, out_dir, meta)
        return RunResult(profile, findings, paths)
    finally:
        if proc is not None:
            proc.terminate()
