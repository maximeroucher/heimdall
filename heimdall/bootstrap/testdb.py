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
    kind: str                        # "sqlite" | "postgres" | "mysql" | "mongo"
    path: str                        # sqlite file path OR db name OR container name
    connect_url: str                 # URL Heimdall connects with (sync for SQL)
    launch_env: dict = field(default_factory=dict)   # env the target launches with
    launch_cwd: str | None = None
    server_url: str | None = None    # admin URL for dropping a server-side db
    container: str | None = None     # docker container name (spawned server), if any

    def remove(self) -> None:
        if self.container:           # a throwaway docker DB server we spawned
            import subprocess
            subprocess.run(["docker", "rm", "-f", self.container],
                           capture_output=True, text=True)
            return
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


def spawn_auto(launch_cwd: str, *, source_path: str | None = None,
               db_url: str | None = None, sqlite_name: str = "heimdall_testdb.sqlite",
               sqlite_env_var: str = "SQLITE_DB", force_kind: str | None = None) -> TestDB:
    """Detect the target's DB engine and provide a matching throwaway ON ITS OWN:

    * an explicit ``--db-url`` (a reachable server you already run) → a fresh
      throwaway database on it (Postgres/MySQL),
    * otherwise a server engine (Postgres / MySQL / Mongo) → spin up a throwaway
      Docker container of that engine and tear it down afterwards,
    * SQLite → a throwaway file.
    """
    from ..discovery.source import detect_db_kind, detect_db_url
    src_url = db_url
    if not src_url and source_path:
        src_url = detect_db_url(source_path)
    kind = force_kind or detect_db_kind(source_path, src_url)
    # a caller-supplied server URL means "use this running server"
    if db_url and (kind in ("postgres", "mysql")):
        return spawn_server_db(db_url, kind=kind)
    if kind in ("postgres", "mysql", "mongo"):
        return spawn_docker_db(kind, source_path=source_path, env_var=sqlite_env_var)
    return spawn_sqlite(launch_cwd, name=sqlite_name, env_var=sqlite_env_var)


# ── Docker-spawned throwaway DB servers (Postgres / MySQL / Mongo) ────────────
_DOCKER_DB = {
    "postgres": {
        "image": "postgres:16-alpine", "port": 5432,
        "env": {"POSTGRES_USER": "heimdall", "POSTGRES_PASSWORD": "heimdall",
                "POSTGRES_DB": "heimdall"},
        "ready": ["pg_isready", "-U", "heimdall", "-d", "heimdall"],
        "url": "postgresql://heimdall:heimdall@127.0.0.1:{port}/heimdall",
        "user": "heimdall", "password": "heimdall", "dbname": "heimdall",
    },
    "mysql": {
        "image": "mysql:8", "port": 3306,
        "env": {"MYSQL_ROOT_PASSWORD": "heimdall", "MYSQL_DATABASE": "heimdall",
                "MYSQL_USER": "heimdall", "MYSQL_PASSWORD": "heimdall"},
        "ready": ["mysqladmin", "ping", "-h", "localhost", "-uroot", "-pheimdall", "--silent"],
        "url": "mysql://root:heimdall@127.0.0.1:{port}/heimdall",
        "user": "root", "password": "heimdall", "dbname": "heimdall",
    },
    "mongo": {
        "image": "mongo:7", "port": 27017,
        "env": {"MONGO_INITDB_ROOT_USERNAME": "heimdall", "MONGO_INITDB_ROOT_PASSWORD": "heimdall"},
        "ready": ["mongosh", "--quiet", "--eval", "db.adminCommand('ping')"],
        "url": "mongodb://heimdall:heimdall@127.0.0.1:{port}/?authSource=admin",
        "user": "heimdall", "password": "heimdall", "dbname": "heimdall",
    },
}


def _docker_available() -> bool:
    import subprocess
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _docker_host_port(name: str, container_port: int) -> int:
    import subprocess
    out = subprocess.check_output(["docker", "port", name, f"{container_port}/tcp"],
                                  text=True).strip().splitlines()
    # e.g. "127.0.0.1:54321" (may list IPv4 + IPv6)
    for line in out:
        hostport = line.rsplit(":", 1)[-1].strip()
        if hostport.isdigit():
            return int(hostport)
    raise RuntimeError(f"could not read mapped port for {name}")


def _wait_docker_ready(name: str, spec: dict, timeout: float = 75.0) -> None:
    import subprocess
    import time
    end = time.time() + timeout
    while time.time() < end:
        r = subprocess.run(["docker", "exec", name, *spec["ready"]],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return
        time.sleep(1.5)
    raise RuntimeError(f"throwaway {name} did not become ready within {timeout:.0f}s")


def spawn_docker_db(kind: str, *, source_path: str | None = None,
                    env_var: str = "DATABASE_URL") -> TestDB:
    """Spin up a throwaway Docker DB server of ``kind`` and return a TestDB whose
    launch_env carries exactly the connection env the target reads."""
    import subprocess
    import uuid as _uuid
    if kind not in _DOCKER_DB:
        raise ValueError(f"no docker recipe for DB kind {kind!r}")
    if not _docker_available():
        raise RuntimeError("Docker is not available to spawn a throwaway DB server "
                           "(start Docker, or pass --db-url to use an existing server)")
    spec = _DOCKER_DB[kind]
    name = f"heimdall-db-{_uuid.uuid4().hex[:10]}"
    args = ["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1::{spec['port']}"]
    for k, v in spec["env"].items():
        args += ["-e", f"{k}={v}"]
    args += [spec["image"]]
    subprocess.run(args, check=True, capture_output=True, text=True)
    try:
        port = _docker_host_port(name, spec["port"])
        _wait_docker_ready(name, spec)
    except Exception:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
        raise
    url = spec["url"].format(port=port)
    from ..discovery.source import detect_db_env_vars
    env_vars = _relevant_db_vars(detect_db_env_vars(source_path) if source_path else set(),
                                 kind)
    # SAFETY GUARD. A server-DB throwaway is only safe if the app can actually be
    # pointed AT it. Unlike SQLite (a file path), a Postgres/MySQL app reads its
    # coordinates from named env vars / config; if we can't detect a single DB var
    # to override (URL, host, …), the app will fall back to ITS OWN config and
    # connect to the REAL database — which we'd then attack. Refuse instead, and
    # tell the user how to proceed safely.
    url_or_host = any(_var_role(v) in ("url", "host") for v in env_vars)
    if not url_or_host:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
        raise RuntimeError(
            f"cannot safely target a throwaway {kind} server: the app exposes no "
            "DB connection env var (URL/host) to override in its source, so it "
            "would boot against its REAL database. Use --spawn-db-kind sqlite if "
            "the app has a SQLite mode, or --db-url to point at a throwaway server "
            "you control (Heimdall will create an isolated database on it).")
    launch_env = _build_launch_env(kind, "127.0.0.1", port, spec, url, env_var, env_vars)
    return TestDB(kind=kind, path=name, connect_url=url, launch_env=launch_env, container=name)


# Which engine-family tokens make a detected env var belong to THIS spawn. A
# Postgres throwaway must not touch REDIS_* or a MONGO_* var, etc.
_KIND_TOKENS = {
    "postgres": ("POSTGRES", "PG", "DATABASE", "SQLALCHEMY", "SQL"),
    "mysql": ("MYSQL", "MARIADB", "DATABASE", "SQLALCHEMY", "SQL"),
    "mongo": ("MONGO", "DATABASE"),
}


def _var_role(name: str) -> str | None:
    """Classify a DB env var by its LAST segment (POSTGRES_HOST → 'host'). The last
    segment (not a substring) is what disambiguates DATABASE_URL (url) from
    DATABASE_DEBUG (None) — the latter must never be set to a connection value."""
    last = name.upper().rsplit("_", 1)[-1]
    return {
        "URL": "url", "URI": "url", "DSN": "url",
        "HOST": "host", "SERVER": "host",
        "PORT": "port",
        "USER": "user", "USERNAME": "user",
        "PASS": "pass", "PASSWORD": "pass",
        "NAME": "name", "DB": "name", "DATABASE": "name", "DBNAME": "name",
    }.get(last)


def _relevant_db_vars(env_vars: set, kind: str) -> set:
    """Keep only the detected vars that (a) belong to this engine family and
    (b) name an actual connection part — dropping REDIS_*/DEBUG/API-key noise and
    cross-engine (SQLITE_*/MONGO_*) vars that a server spawn must not rewrite."""
    tokens = _KIND_TOKENS.get(kind, ())
    keep = set()
    for v in env_vars:
        u = v.upper()
        if "SQLITE" in u or "REDIS" in u:      # never a server-DB coordinate
            continue
        if _var_role(v) and any(t in u for t in tokens):
            keep.add(v)
    return keep


def _build_launch_env(kind: str, host: str, port: int, spec: dict, url: str,
                      env_var: str, env_vars: set) -> dict:
    """Populate every DB env var the app reads (already engine-scoped by
    ``_relevant_db_vars``) with the throwaway's coordinates, plus the standard URL
    name(s) as a fallback."""
    env: dict = {}
    if kind == "mongo":
        for v in ("MONGO_URL", "MONGODB_URI", "MONGO_URI", "MONGODB_URL"):
            env[v] = url
    else:
        # `env_var` defaults to the SQLite *filename* variable (SQLITE_DB). A
        # server-DB connection URL must never be written into a SQLITE_* var — an
        # app that reads it (e.g. `sqlite:///./{SQLITE_DB}`) would treat the URL as
        # a filename and fail to boot, or take a SQLite branch the throwaway server
        # doesn't back. Only honour env_var here when it names a generic URL/DSN
        # sink; otherwise let DATABASE_URL and the detected discrete vars
        # (POSTGRES_HOST/USER/PASSWORD/DB, …) carry the coordinates.
        if env_var and "SQLITE" not in env_var.upper():
            env[env_var] = url
        env["DATABASE_URL"] = url
    # If the app has no separate PORT var (it interpolates HOST straight into a
    # connection URL, e.g. `postgresql://u:p@{POSTGRES_HOST}/{DB}`), fold the
    # throwaway's port INTO the host value — otherwise the app would connect to
    # the engine's default port (5432/3306), which is where the *real* server
    # usually lives. When a PORT var does exist we keep host and port separate.
    has_port_var = any(_var_role(v) == "port" for v in env_vars)
    host_value = host if has_port_var else f"{host}:{port}"
    role_value = {"url": url, "host": host_value, "port": str(port),
                  "user": spec["user"], "pass": spec["password"],
                  "name": spec["dbname"]}
    for name in env_vars:
        role = _var_role(name)
        if role in role_value:
            env[name] = role_value[role]
    return env


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
