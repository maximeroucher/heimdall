"""Spawn a disposable test database of the RIGHT kind for the target.

Heimdall inserts the principals/data it needs directly into a throwaway DB, so
it must match whatever the app uses. It detects the DB from the app's config
(the source-scanned ``DATABASE_URL`` / connection string) and spawns
accordingly:

  * SQLite  — a throwaway file, passed via ``SQLITE_DB`` / ``DATABASE_URL``.
  * Postgres / MySQL — a fresh throwaway DATABASE created on the SAME server
    (``CREATE DATABASE heimdall_test_<rand>``), passed via ``DATABASE_URL``, and
    dropped afterwards. The app's launch command then migrates+seeds it.

A ``TestDB`` yields the SQLAlchemy URL Heimdall connects with, the env the target
must launch with, and a ``remove()`` that tears the throwaway down.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TestDB:
    kind: str                        # "sqlite" | "postgres" | "mysql"
    path: str                        # sqlite file path OR the throwaway db name
    connect_url: str                 # SQLAlchemy URL Heimdall connects with (sync)
    launch_env: dict = field(default_factory=dict)   # env the target launches with
    launch_cwd: str | None = None
    server_url: str | None = None    # admin URL for dropping a server-side db

    def remove(self) -> None:
        if self.kind == "sqlite":
            for suffix in ("", "-wal", "-shm", "-journal"):
                try:
                    os.remove(self.path + suffix)
                except OSError:
                    pass
        elif self.server_url:
            _drop_server_db(self.server_url, self.path, self.kind)


# ── dispatcher ────────────────────────────────────────────────────────────────

def spawn(launch_cwd: str, *, source_db_url: str | None = None,
          sqlite_name: str = "heimdall_testdb.sqlite",
          sqlite_env_var: str = "SQLITE_DB") -> TestDB:
    """Spawn a throwaway DB matching ``source_db_url`` (the app's detected DB).

    Postgres/MySQL URLs → a fresh server-side database; anything else → SQLite.
    """
    driver = (source_db_url or "").split("://", 1)[0].split("+", 1)[0].lower()
    if driver in ("postgresql", "postgres", "psql"):
        return spawn_server_db(source_db_url, kind="postgres")
    if driver in ("mysql", "mariadb"):
        return spawn_server_db(source_db_url, kind="mysql")
    return spawn_sqlite(launch_cwd, name=sqlite_name, env_var=sqlite_env_var)


# ── SQLite ────────────────────────────────────────────────────────────────────

def spawn_sqlite(launch_cwd: str, *, name: str = "heimdall_testdb.sqlite",
                 env_var: str = "SQLITE_DB", relative_filename: bool = True) -> TestDB:
    cwd = Path(launch_cwd).resolve()
    path = cwd / name
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.remove(str(path) + suffix)
        except OSError:
            pass
    if env_var.upper() == "DATABASE_URL":
        env = {env_var: f"sqlite:///{path}"}
    else:
        env = {env_var: name if relative_filename else str(path)}
    return TestDB(kind="sqlite", path=str(path), connect_url=f"sqlite:///{path}",
                  launch_env=env, launch_cwd=str(cwd))


# ── Server DBs (Postgres / MySQL) ─────────────────────────────────────────────

def _sync_driver(url: str) -> str:
    """Force a sync driver (so create_engine works from the sync runner) and pin
    the host to 127.0.0.1 — 'localhost' resolves to IPv6 ::1 first, which many
    Docker/OrbStack port mappings answer flakily or not at all."""
    from sqlalchemy.engine import make_url
    u = make_url(url)
    if u.host == "localhost":
        u = u.set(host="127.0.0.1")
    back = u.get_backend_name()
    if back == "postgresql":
        drv = ("postgresql+psycopg2" if _have("psycopg2")
               else "postgresql+psycopg" if _have("psycopg") else "postgresql")
        u = u.set(drivername=drv)
    elif back == "mysql" and _have("pymysql"):
        u = u.set(drivername="mysql+pymysql")
    # str(URL) MASKS the password (-> '***'); render it in full for real connects.
    return u.render_as_string(hide_password=False)


def _have(mod: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(mod) is not None


def _admin_engine(server_url: str, kind: str):
    """A sync AUTOCOMMIT engine on the server's admin database, with a short
    connect retry (Docker/OrbStack port mappings occasionally flake the first
    connection)."""
    import time

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    src = make_url(_sync_driver(server_url))
    admin_db = "postgres" if kind == "postgres" else src.database
    eng = create_engine(src.set(database=admin_db), isolation_level="AUTOCOMMIT",
                        connect_args={"connect_timeout": 8} if kind == "postgres" else {})
    last = None
    for attempt in range(4):
        try:
            with eng.connect() as c:
                c.execute(text("SELECT 1"))
            return eng, src
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.5 * (attempt + 1))
    raise last


def spawn_server_db(server_url: str, *, kind: str) -> TestDB:
    """CREATE a fresh throwaway database on the app's DB server; return a TestDB
    whose launch_env points the target's DATABASE_URL at it."""
    from sqlalchemy import text
    from sqlalchemy.engine import make_url

    dbname = f"heimdall_test_{uuid.uuid4().hex[:10]}"
    admin, src = _admin_engine(server_url, kind)
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{dbname}"'))
        c.execute(text(f'CREATE DATABASE "{dbname}"'))
    admin.dispose()

    # The URL the APP launches with keeps the app's own (possibly async) driver;
    # only the database name changes (and localhost -> 127.0.0.1 to dodge the same
    # IPv6 flakiness). render_as_string(hide_password=False) — str() masks the pw.
    au = make_url(server_url).set(database=dbname)
    if au.host == "localhost":
        au = au.set(host="127.0.0.1")
    app_url = au.render_as_string(hide_password=False)
    connect_url = src.set(database=dbname).render_as_string(hide_password=False)
    return TestDB(kind=kind, path=dbname, connect_url=connect_url,
                  launch_env={"DATABASE_URL": app_url}, server_url=server_url)


def _drop_server_db(server_url: str, dbname: str, kind: str) -> None:
    try:
        from sqlalchemy import text
        admin, _ = _admin_engine(server_url, kind)
        with admin.connect() as c:
            if kind == "postgres":
                c.execute(text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :d AND pid <> pg_backend_pid()"), {"d": dbname})
            c.execute(text(f'DROP DATABASE IF EXISTS "{dbname}"'))
        admin.dispose()
    except Exception:  # noqa: BLE001 — best-effort cleanup
        pass
