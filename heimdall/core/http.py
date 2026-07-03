"""Thin ``requests`` wrapper: base-url joining + flexible Authorization.

Transparently backs off on ``429 Too Many Requests`` so the target's own rate
limiter can't poison later probes (a 429 must never be misread as "secure").
Callers that specifically want to *observe* raw 429s — the a07 rate-limit
detector — pass ``retry_429=False``.
"""

from __future__ import annotations

import time
from typing import Any

import requests

_BACKOFF = (0.5, 1.5, 3.0)      # per-attempt sleeps
_MAX_WAIT = 6.0                 # cap any single Retry-After honoured


class HttpClient:
    def __init__(self, base_url: str, *, scheme: str = "Bearer", timeout: float = 30.0,
                 auth_kind: str = "bearer", credential_name: str = ""):
        self.base_url = base_url.rstrip("/")
        self.scheme = scheme
        self.timeout = timeout
        self.auth_kind = auth_kind
        self.credential_name = credential_name
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "heimdall/0.1 (+authorized security test)"

    def _apply_credential(self, token: str, headers: dict, kw: dict) -> None:
        """Attach ``token`` the way this app expects (bearer / basic / api-key
        header or query / session cookie) so non-JWT auth works transparently."""
        kind = self.auth_kind
        if kind == "basic":
            headers["Authorization"] = f"Basic {token}"
        elif kind == "apikey_header":
            headers[self.credential_name or "X-API-Key"] = token
        elif kind == "apikey_query":
            params = dict(kw.get("params") or {})
            params[self.credential_name or "api_key"] = token
            kw["params"] = params
        elif kind == "cookie":
            existing = headers.get("Cookie")
            crumb = f"{self.credential_name or 'session'}={token}"
            headers["Cookie"] = f"{existing}; {crumb}" if existing else crumb
        else:  # bearer (default)
            headers["Authorization"] = f"{self.scheme} {token}"

    def url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def req(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        raw_authorization: str | None = None,
        retry_429: bool = True,
        **kw: Any,
    ) -> requests.Response:
        headers = dict(kw.pop("headers", {}) or {})
        if raw_authorization is not None:
            headers["Authorization"] = raw_authorization
        elif token:
            self._apply_credential(token, headers, kw)
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", False)
        url = self.url(path)
        resp = self.s.request(method, url, headers=headers, **kw)
        if not retry_429:
            return resp
        for sleep in _BACKOFF:
            if resp.status_code != 429:
                return resp
            wait = sleep
            ra = resp.headers.get("Retry-After")
            if ra and ra.isdigit():
                wait = min(float(ra), _MAX_WAIT)
            time.sleep(wait)
            resp = self.s.request(method, url, headers=headers, **kw)
        return resp

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
