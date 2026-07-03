"""Command-line entrypoint: ``python -m heimdall`` / ``heimdall``."""

from __future__ import annotations

import argparse
import sys

from .bootstrap.principals import Cred
from .config import TargetConfig
from .discovery import discover, summarize
from .modules.base import REGISTRY
from .runner import run


def _parse_cred(spec: str) -> Cred:
    # "label:role:identifier:password"
    parts = spec.split(":", 3)
    if len(parts) != 4:
        raise argparse.ArgumentTypeError(
            f"credential must be label:role:identifier:password (got {spec!r})")
    label, role, ident, pw = parts
    return Cred(label=label, role=role, identifier=ident, password=pw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="heimdall",
        description="Self-discovering OWASP pentest for FastAPI apps.")
    ap.add_argument("--url", help="target base URL, e.g. http://127.0.0.1:8000")
    ap.add_argument("--source", help="path to the target's source tree (white-box)")
    ap.add_argument("--name", help="friendly app name for the report")
    ap.add_argument("--config", help="TOML/JSON target config file")
    ap.add_argument("--cred", action="append", default=[], type=_parse_cred,
                    metavar="label:role:identifier:password",
                    help="login credential (repeatable)")
    ap.add_argument("--launch", help="shell command to boot the target first")
    ap.add_argument("--launch-cwd", help="cwd for --launch")
    ap.add_argument("--out", help="report output directory (default ./heimdall-report)")
    ap.add_argument("--only", default="", help="comma list of module keys to run")
    ap.add_argument("--skip", default="", help="comma list of module keys to skip")
    ap.add_argument("--safe", action="store_true", help="non-destructive: skip mutating tests")
    ap.add_argument("--no-attacker", action="store_true",
                    help="do not self-register a low-priv attacker account")
    ap.add_argument("--discover-only", action="store_true",
                    help="print the discovered app profile and exit (no attacks)")
    ap.add_argument("--list-modules", action="store_true", help="list modules and exit")
    ap.add_argument("--i-have-authorization", action="store_true",
                    help="permit a non-loopback target (authorized use only)")
    args = ap.parse_args(argv)

    if args.list_modules:
        # import to populate the registry
        from .runner import _import_all_modules
        _import_all_modules()
        for spec in sorted(REGISTRY.values(), key=lambda m: m.key):
            print(f"  {spec.key:8} {spec.name}")
        return 0

    if args.config:
        cfg = TargetConfig.load(args.config)
        if args.url:
            cfg.base_url = args.url
        if args.source:
            cfg.source_path = args.source
        if args.cred:
            cfg.credentials.extend(args.cred)
    else:
        if not args.url:
            ap.error("provide --url (or --config)")
        cfg = TargetConfig(
            base_url=args.url, name=args.name, source_path=args.source,
            launch=args.launch, launch_cwd=args.launch_cwd,
            credentials=args.cred, make_attacker=not args.no_attacker,
        )
    if args.i_have_authorization:
        cfg.authorized = True

    if args.discover_only:
        from .core.guardrail import assert_target_allowed
        assert_target_allowed(cfg.base_url, cfg.authorized)
        profile = discover(cfg.base_url, source_path=cfg.source_path, app_name=cfg.name)
        print(summarize(profile))
        if profile.secrets:
            print("\nCandidate secrets:")
            for s in profile.secrets:
                print(f"  [{s.kind}] {s.name} = {s.value!r}  ({s.source})")
        print("\nNotes:")
        for n in profile.notes:
            print(f"  · {n}")
        return 0

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}

    result = run(cfg, out_dir=args.out, only=only or None, skip=skip or None, safe=args.safe)

    counts = result.counts()
    print("\n" + "=" * 60)
    print(f"[=] {len(result.findings)} findings — "
          + ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())))
    for f in sorted(result.issues, key=lambda x: x.severity):
        print(f"    {f.severity:9} {f.owasp}  {f.title}")
    print(f"\n[=] Report:  {result.report_paths[1]}")
    print(f"[=] JSON:    {result.report_paths[0]}")
    # exit non-zero if anything HIGH/CRITICAL, handy for CI gating
    bad = [f for f in result.issues if f.severity in ("HIGH", "CRITICAL")]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
