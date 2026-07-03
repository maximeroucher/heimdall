"""Spawn a disposable test database for the target, so Heimdall can insert the
principals/data it needs directly — no email-activation dance required.

The simplest universally-available option is a throwaway SQLite file: no server,
no residue, and most SQLAlchemy apps accept it via a single env var (the app:
``SQLITE_DB``; many others: ``DATABASE_URL``). Heimdall creates the file, tells
the target to use it through the launch environment, lets the app build its
schema on first boot, then connects and seeds test data.

A ``TestDB`` yields both the SQLAlchemy URL Heimdall connects with and the env
overrides the target must launch with — which can differ: an app that builds
``sqlite+aiosqlite:///./<name>`` from a bare ``SQLITE_DB`` filename needs the
relative name, while Heimdall connects with the absolute ``sqlite:///<path>``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TestDB:
    #: absolute path to the sqlite file Heimdall creates/owns
    path: str
    #: SQLAlchemy URL Heimdall itself connects with (sync driver)
    connect_url: str
    #: environment the target must be launched with to use this DB
    launch_env: dict = field(default_factory=dict)
    #: cwd the target must launch from (for relative-filename sqlite URLs)
    launch_cwd: str | None = None

    def remove(self) -> None:
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.remove(self.path + suffix)
            except OSError:
                pass


def spawn_sqlite(
    launch_cwd: str,
    *,
    name: str = "heimdall_testdb.sqlite",
    env_var: str = "SQLITE_DB",
    relative_filename: bool = True,
) -> TestDB:
    """Create a fresh sqlite DB file under ``launch_cwd`` and return a ``TestDB``.

    ``relative_filename=True`` (the default, matches apps that do
    ``sqlite+aiosqlite:///./{SQLITE_DB}``) puts just the basename in the env var;
    ``env_var`` selects which variable the target reads (``SQLITE_DB`` for
    the app-style, or set it to ``DATABASE_URL`` for apps that take a full URL).
    """
    cwd = Path(launch_cwd).resolve()
    path = cwd / name
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.remove(str(path) + suffix)   # ensure a clean slate
        except OSError:
            pass

    if env_var.upper() == "DATABASE_URL":
        env = {env_var: f"sqlite:///{path}"}
    else:
        env = {env_var: name if relative_filename else str(path)}

    return TestDB(
        path=str(path),
        connect_url=f"sqlite:///{path}",
        launch_env=env,
        launch_cwd=str(cwd),
    )
