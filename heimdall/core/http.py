"""Thin ``requests`` wrapper: base-url joining + flexible Authorization."""

from __future__ import annotations

from typing import Any

import requests


class HttpClient:
    def __init__(self, base_url: str, *, scheme: str = "Bearer", timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.scheme = scheme
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "heimdall/0.1 (+authorized security test)"

    def url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def req(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        raw_authorization: str | None = None,
        **kw: Any,
    ) -> requests.Response:
        headers = dict(kw.pop("headers", {}) or {})
        if raw_authorization is not None:
            headers["Authorization"] = raw_authorization
        elif token:
            headers["Authorization"] = f"{self.scheme} {token}"
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", False)
        return self.s.request(method, self.url(path), headers=headers, **kw)

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, **kw):
        return self.req("POST", path, **kw)

    def put(self, path, **kw):
        return self.req("PUT", path, **kw)

    def patch(self, path, **kw):
        return self.req("PATCH", path, **kw)

    def delete(self, path, **kw):
        return self.req("DELETE", path, **kw)
