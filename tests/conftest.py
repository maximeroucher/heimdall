"""Shared fixtures: build synthetic OpenAPI specs and profiles for unit tests."""

import pytest

from heimdall.core.model import AppProfile
from heimdall.discovery import auth as auth_detect
from heimdall.discovery import openapi as oa


def make_spec(paths, security_schemes=None):
    spec = {"openapi": "3.1.0", "info": {"title": "T"}, "paths": paths}
    if security_schemes:
        spec["components"] = {"securitySchemes": security_schemes}
    return spec


@pytest.fixture
def json_login_spec():
    return make_spec(
        {
            "/core/auth/login": {"post": {
                "operationId": "login",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"username": {"type": "string"},
                                   "password": {"type": "string"}},
                }}}},
            }},
            "/core/auth/register": {"post": {
                "operationId": "register",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"email": {"type": "string"},
                                   "password": {"type": "string"}},
                }}}},
            }},
            "/users/me": {"get": {"operationId": "me",
                                  "security": [{"bearer": []}]}},
            "/users/{user_id}": {"get": {
                "operationId": "get_user",
                "parameters": [{"name": "user_id", "in": "path",
                                "required": True, "schema": {"type": "string"}}],
                "security": [{"bearer": []}],
            }},
            "/items": {"get": {
                "operationId": "list_items",
                "parameters": [{"name": "q", "in": "query",
                                "schema": {"type": "string"}}],
            }},
        },
        {"bearer": {"type": "http", "scheme": "bearer"}},
    )


@pytest.fixture
def profile_from(json_login_spec):
    rm = oa.parse_routes(json_login_spec)
    p = AppProfile(base_url="http://127.0.0.1:8000", routes=rm)
    p.auth = auth_detect.detect_auth(rm)
    return p
