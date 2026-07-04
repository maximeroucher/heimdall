"""Module registry. A module is a ``run(ctx)`` function tagged with metadata.

Register with the ``@module(...)`` decorator; the runner imports every file in
this package to populate ``REGISTRY`` and then executes the selected modules in
declaration order.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..core.context import Context

ModuleFn = Callable[[Context], None]


@dataclass
class ModuleSpec:
    key: str
    name: str
    fn: ModuleFn
    order: int
    destructive: bool = False


REGISTRY: dict[str, ModuleSpec] = {}
_counter = [0]


def module(key: str, name: str, *, destructive: bool = False):
    def deco(fn: ModuleFn) -> ModuleFn:
        _counter[0] += 1
        REGISTRY[key] = ModuleSpec(key, name, fn, _counter[0], destructive)
        return fn
    return deco


def ordered() -> list[ModuleSpec]:
    return sorted(REGISTRY.values(), key=lambda m: m.order)


# ── small shared helpers used across modules ─────────────────────────────────

ID_PARAM_HINT = ("id", "uuid", "pk", "slug")


def looks_like_id_param(name: str) -> bool:
    n = name.lower()
    return any(h == n or n.endswith("_" + h) or n.endswith(h) for h in ID_PARAM_HINT)


def body_says_error(text: str) -> bool:
    t = text.lower()
    return any(s in t for s in (
        "traceback (most recent call last)", "sqlalchemy", "psycopg",
        "syntax error at or near", "unterminated quoted string",
        "integrityerror", "programmingerror", "operationalerror",
        # SQLite (stdlib sqlite3 / aiosqlite) — extremely common, its raw errors
        # read differently from Postgres/MySQL and were slipping through.
        "unrecognized token", "sqlite3.", "no such column", "no such table",
        "sqlite_error", "malformed database", "incomplete input",
        # MySQL / MariaDB driver errors.
        "you have an error in your sql syntax", "warning: mysqli", "mysqlnd",
    ))
