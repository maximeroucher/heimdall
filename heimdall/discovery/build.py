"""Assemble an ``AppProfile`` from a live target (+ optional source tree)."""

from __future__ import annotations

from ..core.model import AppProfile, RouteMap
from . import auth as auth_detect
from . import openapi as oa
from . import source as src


def discover(base_url: str, *, source_path: str | None = None,
             app_name: str | None = None) -> AppProfile:
    base_url = base_url.rstrip("/")
    profile = AppProfile(base_url=base_url, source_path=source_path)

    # 1. OpenAPI -> routes
    fetched = oa.fetch_openapi(base_url)
    if fetched is not None:
        oa_path, spec = fetched
        profile.routes = oa.parse_routes(spec)
        info = spec.get("info", {})
        profile.app_name = app_name or info.get("title") or "target"
        profile.notes.append(
            f"OpenAPI at {oa_path}: {len(profile.routes)} operations, "
            f"{len(profile.routes.secured())} require auth"
        )
    else:
        profile.routes = RouteMap()
        profile.app_name = app_name or "target"
        profile.notes.append(
            "no OpenAPI document reachable — running in reduced (blind) mode"
        )

    # 2. auth shape
    profile.auth = auth_detect.detect_auth(profile.routes)
    if profile.auth.login_path:
        profile.notes.append(
            f"login: {profile.auth.login_style} POST {profile.auth.login_path} "
            f"({profile.auth.username_field}/{profile.auth.password_field})"
        )
    else:
        profile.notes.append("no login endpoint auto-detected")

    # 3. public docs exposure (misconfig signal, also used by a05)
    profile.docs_paths = oa.discover_doc_paths(base_url)

    # 4. optional white-box
    if source_path:
        profile.secrets = src.scan_secrets(source_path)
        if profile.secrets:
            profile.notes.append(
                f"source scan: {len(profile.secrets)} candidate secret(s) found"
            )
    return profile


def summarize(profile: AppProfile) -> str:
    L = [
        f"App:       {profile.app_name}",
        f"Base URL:  {profile.base_url}",
        f"Routes:    {len(profile.routes)} ({len(profile.routes.secured())} secured, "
        f"{len(profile.routes.with_path_params())} with path params)",
        f"Login:     {profile.auth.login_path or '—'} "
        f"[{profile.auth.login_style}]",
        f"Register:  {profile.auth.register_path or '—'}",
        f"Me:        {profile.auth.me_path or '—'}",
        f"Docs open: {', '.join(profile.docs_paths) or '—'}",
        f"Secrets:   {len(profile.secrets)} candidate(s)"
        + (f" (source: {profile.source_path})" if profile.source_path else " (no source given)"),
    ]
    return "\n".join(L)
