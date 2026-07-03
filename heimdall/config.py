"""Target configuration: how to reach, launch, and authenticate to the app.

Can be built programmatically (the library is importable) or loaded from a
TOML/JSON file (the CLI). A config never contains exploit logic — only the
facts Heimdall can't safely guess: the base URL, optional source tree, an
optional launch command, and privileged credentials to log in with.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .bootstrap.principals import Cred


@dataclass
class TargetConfig:
    base_url: str
    name: str | None = None
    source_path: str | None = None
    launch: str | None = None            # shell command to boot the target
    launch_cwd: str | None = None
    launch_env: dict = field(default_factory=dict)
    credentials: list[Cred] = field(default_factory=list)
    authorized: bool = False             # allow a non-loopback target
    make_attacker: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> "TargetConfig":
        creds = []
        for c in d.get("credentials", []):
            creds.append(Cred(
                label=c["label"],
                role=c.get("role", "user"),
                identifier=c.get("identifier") or c.get("email") or c.get("username"),
                password=c["password"],
            ))
        return cls(
            base_url=d["base_url"],
            name=d.get("name"),
            source_path=d.get("source_path"),
            launch=d.get("launch"),
            launch_cwd=d.get("launch_cwd"),
            launch_env=d.get("launch_env", {}),
            credentials=creds,
            authorized=d.get("authorized", False),
            make_attacker=d.get("make_attacker", True),
        )

    @classmethod
    def load(cls, path: str) -> "TargetConfig":
        p = Path(path)
        text = p.read_text()
        if p.suffix in (".toml",):
            data = _load_toml(text)
        else:
            data = json.loads(text)
        # allow a top-level [target] table
        if "target" in data and "base_url" not in data:
            data = data["target"]
        return cls.from_dict(data)


def _load_toml(text: str) -> dict:
    try:
        import tomllib  # py3.11+
        return tomllib.loads(text)
    except ModuleNotFoundError:
        try:
            import tomli
            return tomli.loads(text)
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise SystemExit(
                "TOML config needs Python 3.11+ or `pip install tomli`; "
                "or use a .json config instead."
            ) from exc
