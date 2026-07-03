"""The ``Context`` handed to every exploit module.

It bundles the discovered ``AppProfile``, an HTTP client wired to the target,
the findings sink, and run-mode flags. A module only ever touches ``ctx`` — it
stays fully target-agnostic.
"""

from __future__ import annotations

from typing import Any

from .findings import Finding
from .http import HttpClient
from .model import AppProfile, Principal


class Context:
    def __init__(self, profile: AppProfile, *, safe: bool = False, verbose: bool = True):
        self.profile = profile
        self.safe = safe
        self.verbose = verbose
        self.http = HttpClient(
            profile.base_url, scheme=profile.auth.header_scheme,
            auth_kind=profile.auth.auth_kind,
            credential_name=profile.auth.credential_name)
        self._findings: list[Finding] = []
        self._current_module = ""

    # -- convenience proxies ---------------------------------------------------
    @property
    def base_url(self) -> str:
        return self.profile.base_url

    @property
    def routes(self):
        return self.profile.routes

    @property
    def auth(self):
        return self.profile.auth

    def principal(self, *roles: str) -> Principal | None:
        return self.profile.principal(*roles)

    # -- HTTP passthrough ------------------------------------------------------
    def get(self, path, **kw):
        return self.http.get(path, **kw)

    def post(self, path, **kw):
        return self.http.post(path, **kw)

    def put(self, path, **kw):
        return self.http.put(path, **kw)

    def patch(self, path, **kw):
        return self.http.patch(path, **kw)

    def delete(self, path, **kw):
        return self.http.delete(path, **kw)

    def request(self, method, path, **kw):
        return self.http.req(method, path, **kw)

    # -- findings + notes ------------------------------------------------------
    def finding(self, **kw: Any) -> Finding:
        f = Finding(**kw)
        f.module = self._current_module
        self._findings.append(f)
        badge = f.severity
        print(f"      [{badge}] {f.title}")
        return f

    def findings(self) -> list[Finding]:
        return list(self._findings)

    def note(self, msg: str) -> None:
        self.profile.notes.append(msg)
        if self.verbose:
            print(f"      · {msg}")
