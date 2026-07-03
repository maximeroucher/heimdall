"""Pure data structures describing a discovered target.

These are populated by the ``discovery`` package and consumed by the exploit
modules, so a module never hard-codes a path or a login shape — it reads them
off the ``AppProfile``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Route:
    """One (method, path) operation from the OpenAPI document."""
    path: str                        # "/users/{user_id}"
    method: str                      # "GET" (upper-case)
    operation_id: str = ""
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    secured: bool = False            # has a non-empty security requirement
    path_params: list[str] = field(default_factory=list)
    query_params: list[dict] = field(default_factory=list)   # openapi param objs
    body_schema: dict | None = None  # resolved requestBody json schema
    raw: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def has_path_param(self) -> bool:
        return bool(self.path_params)

    def fill_path(self, values: dict[str, Any]) -> str:
        out = self.path
        for name in self.path_params:
            out = out.replace("{" + name + "}", str(values.get(name, "1")))
        return out


@dataclass
class RouteMap:
    routes: list[Route] = field(default_factory=list)
    openapi: dict = field(default_factory=dict)
    components: dict = field(default_factory=dict)   # schemas for $ref resolution

    def __iter__(self):
        return iter(self.routes)

    def __len__(self):
        return len(self.routes)

    def secured(self) -> list[Route]:
        return [r for r in self.routes if r.secured]

    def with_path_params(self) -> list[Route]:
        return [r for r in self.routes if r.has_path_param]

    def by_method(self, *methods: str) -> list[Route]:
        ms = {m.upper() for m in methods}
        return [r for r in self.routes if r.method in ms]

    def find(self, substr: str, method: str | None = None) -> list[Route]:
        s = substr.lower()
        out = [r for r in self.routes if s in r.path.lower()]
        if method:
            out = [r for r in out if r.method == method.upper()]
        return out

    def first(self, substr: str, method: str | None = None) -> Route | None:
        hits = self.find(substr, method)
        return hits[0] if hits else None


@dataclass
class AuthProfile:
    """How to authenticate against the target, learned at discovery time."""
    login_path: str | None = None
    login_style: str = "json"        # "json" | "form" | "oauth_password" | "unknown"
    username_field: str = "username"
    password_field: str = "password"
    token_response_field: str = "access_token"
    scopes_field: str | None = None  # e.g. OAuth "scope" sent on token request
    register_path: str | None = None
    register_fields: list[str] = field(default_factory=list)
    me_path: str | None = None       # a "current user" echo endpoint
    logout_path: str | None = None
    header_scheme: str = "Bearer"    # Authorization: <scheme> <token>

    # How the credential is carried, so non-JWT/non-bearer apps work too.
    auth_kind: str = "bearer"        # bearer | basic | apikey_header | apikey_query | cookie
    credential_name: str = ""        # header / query / cookie name for apikey|cookie kinds

    # JWT facts, filled once we hold a real token.
    jwt_alg: str | None = None
    jwt_header: dict = field(default_factory=dict)
    jwt_claims: dict = field(default_factory=dict)
    is_jwt: bool = False


@dataclass
class Principal:
    """An authenticated (or would-be) actor used by the modules."""
    label: str
    role: str = "user"               # free-form: user | admin | attacker | ...
    user_id: str | None = None
    email: str | None = None
    username: str | None = None
    password: str | None = None
    token: str | None = None         # bearer token
    supplied: bool = False           # credentials given by the user vs. self-made
    extra: dict = field(default_factory=dict)

    @property
    def authed(self) -> bool:
        return bool(self.token)


@dataclass
class Secret:
    """A candidate secret found during (optional) white-box source scanning."""
    name: str
    value: str
    source: str                      # file:line
    kind: str = "generic"            # jwt_secret | db_url | api_key | ...


@dataclass
class AppProfile:
    """Everything discovery learned about the target, handed to every module."""
    base_url: str
    app_name: str = "target"
    framework: str = "FastAPI"
    source_path: str | None = None
    routes: RouteMap = field(default_factory=RouteMap)
    auth: AuthProfile = field(default_factory=AuthProfile)
    principals: dict[str, Principal] = field(default_factory=dict)
    secrets: list[Secret] = field(default_factory=list)
    docs_paths: list[str] = field(default_factory=list)   # /docs, /redoc, /openapi.json
    notes: list[str] = field(default_factory=list)

    def principal(self, *roles: str) -> Principal | None:
        """Best authenticated principal matching any of ``roles`` (in order)."""
        for role in roles:
            for p in self.principals.values():
                if p.role == role and p.authed:
                    return p
        return None

    def any_authed(self) -> Principal | None:
        for p in self.principals.values():
            if p.authed:
                return p
        return None
