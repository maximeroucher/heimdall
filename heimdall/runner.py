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

    # Spawn a throwaway DB the target will use, so Heimdall can insert test data.
    testdb = None
    launch_env = dict(config.launch_env)
    db_url = config.db_url
    if config.spawn_db:
        from .bootstrap import testdb as testdb_mod
        if not config.launch_cwd:
            raise SystemExit("[!] spawn_db requires launch_cwd")
        # Auto-detect the app's DB kind from its config so we spawn the right
        # throwaway (a Postgres/MySQL database, or a SQLite file).
        source_db = config.db_url
        if not source_db and config.source_path:
            from .discovery.source import detect_db_url
            source_db = detect_db_url(config.source_path)
        testdb = testdb_mod.spawn(
            config.launch_cwd, source_db_url=source_db,
            sqlite_name=config.spawn_db_name, sqlite_env_var=config.spawn_db_env_var)
        launch_env.update(testdb.launch_env)
        db_url = testdb.connect_url
        print(f"[*] spawned throwaway {testdb.kind} DB: {testdb.path}")
        if testdb.kind != "sqlite":
            print(f"[*] target will launch with DATABASE_URL -> …/{testdb.path}")

    proc = None
    if config.launch:
        print(f"[*] launching target: {config.launch}")
        proc = server.launch(config.launch, cwd=config.launch_cwd, env=launch_env)
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

        if config.provision_low_priv or config.provision_admins:
            _provision(config, profile, principals, db_url)

        if config.mint_scoped:
            _mint_scoped_tokens(profile, principals)

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
        _resolve_source_locations(config.source_path, findings)
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
        if testdb is not None:
            testdb.remove()


def _resolve_source_locations(source_path, findings) -> None:
    """Fill each finding's `location` (file:line) by mapping its route back to the
    handler in the source tree — so the report points at the exact code to fix."""
    if not source_path:
        return
    from .discovery.source import index_routes, locate_route
    index = index_routes(source_path)
    if not index:
        return
    for f in findings:
        if f.location or not f.route or " " not in f.route:
            continue
        method, _, path = f.route.partition(" ")
        loc = locate_route(index, method.strip(), path.strip())
        if loc:
            f.location = loc


def _provision(config, profile, principals: dict, db_url: str | None) -> None:
    """Insert low-priv / admin test users into the throwaway DB Heimdall owns."""
    from .bootstrap.provision import ProvisionRequest, provision

    req = ProvisionRequest(
        low_priv=config.provision_low_priv,
        admins=config.provision_admins,
        password=config.provision_password,
        db_url=db_url,
    )
    print(f"[*] self-provisioning {req.low_priv} low-priv + {req.admins} admin user(s)…")
    res = provision(profile, req)
    for n in res.notes:
        print(f"      · {n}")
    for p in res.principals:
        principals[p.label] = p


def _mint_scoped_tokens(profile, principals: dict) -> None:
    """When the signing secret is recoverable, re-issue EVERY principal an
    API-scoped token. Needed on apps whose login tokens are scope-limited (e.g.
    the app's 'auth'-scoped simple_token that 403s the whole API) — this lifts
    supplied admins AND provisioned users to a usable scope so the authorization
    matrix (BFLA both directions, BOLA) can actually be exercised."""
    from .bootstrap import minting

    template = next((p.token for p in principals.values() if p.token), None)
    if not template:
        return
    secret = minting.recover_secret(profile, template)
    if not secret:
        return
    scopes = minting.declared_scopes(profile)
    if not scopes:
        return
    n = 0
    for p in principals.values():
        if not p.token:
            continue
        minted = minting.mint(p.token, secret, sub=p.user_id, scopes=scopes)
        if minted:
            p.token = minted
            p.extra["minted_scopes"] = scopes
            n += 1
    if n:
        print(f"[*] signing secret recovered → minted {scopes!r}-scoped tokens "
              f"for {n} principal(s)")
