"""A01/A05 — WebSocket security.

WebSocket endpoints are invisible to black-box discovery (FastAPI never lists
them in ``openapi.json``), so this module finds them by scanning the source tree
for ``@app.websocket`` / ``@router.websocket`` decorators (needs ``--source``),
then tests the two issues that actually bite a FastAPI WS:

  * **Missing authentication** — the socket accepts a connection and serves
    application data without any credential. Connect with nothing and see if the
    server pushes data or keeps the channel open instead of rejecting it.
  * **Cross-Site WebSocket Hijacking (CSWSH)** — the handshake doesn't validate
    the ``Origin`` header, so a page on ``attacker.tld`` can open the socket.
    This is only *exploitable* when the WS authenticates with **ambient**
    credentials (cookies), which the attacker's origin sends automatically. If
    the WS instead authenticates with a **token in the first message / query**
    (very common in FastAPI — the token isn't ambient, so a cross-origin page
    can't supply it), a missing Origin check is only defense-in-depth. The
    module distinguishes the two so it doesn't over-report token-gated sockets.

Needs the ``websocket-client`` extra (``pip install 'heimdall-pentest[full]'``);
if absent, the module notes the WS routes it found and skips the live probe.
"""

from __future__ import annotations

import json

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

_ATTACKER_ORIGIN = "https://evil-heimdall-cswsh.test"
# Wordings that mark a frame as an AUTH REJECTION rather than application data —
# kept auth-specific (no bare "token"/"required"/status numbers) so a legitimate
# data stream isn't misread as a rejection (which would hide a real unauth socket).
_AUTH_ERROR_HINTS = ("invalid", "unauth", "forbidden", "denied", "expired",
                     "not authenticated", "missing token", "error", "closed",
                     "authenticat",           # authentication/authenticate required
                     "credential",            # "Could not validate credentials" (JWT default)
                     "not allowed", "permission", "login")
_MAX_ENDPOINTS = 10
_TIMEOUT = 6


@module("websocket", "WebSocket Security")
def run(ctx: Context) -> None:
    src = ctx.profile.source_path
    if not src:
        ctx.note("websocket: no --source given; WS routes aren't in OpenAPI so "
                 "can't be discovered black-box — skipping")
        return
    from ..discovery.source import index_websocket_routes
    ws_routes = index_websocket_routes(src)
    if not ws_routes:
        ctx.note("websocket: no @websocket routes found in the source tree")
        return

    ctx.note(f"websocket: found {len(ws_routes)} declared WS route(s) in source")
    try:
        import websocket  # websocket-client
    except ModuleNotFoundError:
        ctx.finding(
            id="ws-client-missing", owasp="A05", severity="INFO",
            title=f"{len(ws_routes)} WebSocket endpoint(s) found (not live-tested)",
            summary=(
                "Declared WebSocket routes were located in source but the "
                "websocket-client extra isn't installed, so they weren't probed "
                "live. Install heimdall-pentest[full] and re-run to test them for "
                "missing auth and CSWSH (missing Origin validation)."),
            evidence="\n".join(f"  {p}   ({loc})" for p, loc in ws_routes[:15]),
            references=[REFS["A05"]],
            tools=["websocat", "Burp Suite"])
        return

    token = _actor_token(ctx)
    results = []
    tried: set[str] = set()
    for path, loc in ws_routes:
        if path in tried:
            continue
        tried.add(path)
        verdict = _assess(ctx, websocket, path, loc, token)
        if verdict:
            results.append(verdict)
        if len(results) >= _MAX_ENDPOINTS:
            break

    _report(ctx, results)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── ws helpers ───────────────────────────────────────────────────────────────

def _ws_url(base_url: str, path: str) -> str:
    scheme_swapped = base_url.replace("https://", "wss://", 1).replace(
        "http://", "ws://", 1)
    return scheme_swapped.rstrip("/") + "/" + path.lstrip("/")


def _connect(websocket, url: str, *, origin: str | None = None,
             header: list | None = None):
    kw = {"timeout": _TIMEOUT}
    if origin is not None:
        kw["origin"] = origin
    if header:
        kw["header"] = header
    return websocket.create_connection(url, **kw)


def _recv_short(ws, timeout: float = 3.0) -> tuple[str, str]:
    """Return (kind, text): kind ∈ closed|timeout|data|error."""
    try:
        ws.settimeout(timeout)
        msg = ws.recv()
        return "data", msg if isinstance(msg, str) else msg.decode("utf-8", "ignore")
    except Exception as exc:  # noqa: BLE001 — websocket-client raises many types
        name = type(exc).__name__.lower()
        if "closed" in name:
            return "closed", ""
        if "timeout" in name:
            return "timeout", ""
        return "error", str(exc)[:120]


def _looks_authgate(text: str, kind: str) -> bool:
    """Did the server reject/close us for lack of auth?"""
    if kind in ("closed", "error"):
        return True
    return any(h in text.lower() for h in _AUTH_ERROR_HINTS)


# ── assessment ───────────────────────────────────────────────────────────────

def _assess(ctx, websocket, path: str, loc: str, token: str | None) -> dict | None:
    url = _ws_url(ctx.base_url, path)

    # 1) Baseline reachability (legit same-origin, no creds).
    try:
        base = _connect(websocket, url)
    except Exception as exc:  # noqa: BLE001
        name = type(exc).__name__
        # A 4xx/handshake rejection with no creds could itself be auth-at-handshake.
        if "BadStatus" in name:
            return {"path": path, "loc": loc, "reachable": True,
                    "handshake_auth": True, "unauth": False,
                    "origin_validated": None, "explicit_token": None}
        return {"path": path, "loc": loc, "reachable": False, "err": str(exc)[:100]}

    # 2) Is it usable with NO authentication? Nudge it with a benign message and
    #    listen: an auth-gated socket rejects/closes; an open one serves data.
    unauth = False
    try:
        kind, text = _recv_short(base, 2.5)         # some sockets push first
        if kind == "data" and not _looks_authgate(text, kind):
            unauth = True
        else:
            base.send(json.dumps({"heimdall": "probe"}))
            kind, text = _recv_short(base, 2.5)
            if kind == "data" and not _looks_authgate(text, kind):
                unauth = True
    except Exception:  # noqa: BLE001
        pass
    finally:
        _safe_close(base)

    # 3) Origin validation: does an attacker Origin still get a handshake?
    origin_validated = None
    try:
        eviltok = _connect(websocket, url, origin=_ATTACKER_ORIGIN)
        origin_validated = False
        _safe_close(eviltok)
    except Exception as exc:  # noqa: BLE001
        origin_validated = True if "BadStatus" in type(exc).__name__ else None

    # 4) Is auth EXPLICIT (token in first message / query)? If so, a missing
    #    Origin check isn't CSWSH-exploitable (attacker can't supply the token).
    explicit_token = _probe_explicit_token(websocket, url, token) if token else None

    return {"path": path, "loc": loc, "reachable": True, "handshake_auth": False,
            "unauth": unauth, "origin_validated": origin_validated,
            "explicit_token": explicit_token}


def _probe_explicit_token(websocket, url: str, token: str) -> bool | None:
    """True if sending our valid token (first-message or ?token=) gets us in —
    proving auth is non-ambient. None if we couldn't tell."""
    # First-message token — the common FastAPI pattern.
    try:
        ws = _connect(websocket, url)
        ws.send(json.dumps({"token": token}))
        kind, text = _recv_short(ws, 3.0)
        _safe_close(ws)
        if kind == "data" and not _looks_authgate(text, kind):
            return True
    except Exception:  # noqa: BLE001
        pass
    # Query-param token.
    try:
        sep = "&" if "?" in url else "?"
        ws = _connect(websocket, f"{url}{sep}token={token}")
        kind, text = _recv_short(ws, 3.0)
        _safe_close(ws)
        if kind == "data" and not _looks_authgate(text, kind):
            return True
    except Exception:  # noqa: BLE001
        pass
    return None


def _safe_close(ws) -> None:
    try:
        ws.close()
    except Exception:  # noqa: BLE001
        pass


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx: Context, results: list[dict]) -> None:
    live = [r for r in results if r.get("reachable")]
    if not live:
        ctx.note("websocket: declared WS routes weren't reachable at the tested "
                 "paths (router prefix?) — no live result")
        return

    unauth = [r for r in live if r.get("unauth")]
    # Origin findings only concern endpoints that DID enforce auth — an unauth
    # socket is already the worse (HIGH) finding, so don't double-list it.
    unauth_paths = {r["path"] for r in unauth}
    gated = [r for r in live if r["path"] not in unauth_paths]
    # No Origin check AND not clearly token-gated → CSWSH candidate.
    cswsh = [r for r in gated if r.get("origin_validated") is False
             and not r.get("explicit_token")]
    # No Origin check but explicit-token auth confirmed → defense-in-depth only.
    no_origin_dib = [r for r in gated if r.get("origin_validated") is False
                     and r.get("explicit_token")]

    if unauth:
        r = unauth[0]
        ctx.finding(
            id="ws-unauthenticated", owasp="A01", severity="HIGH",
            title=f"WebSocket {r['path']} serves data without authentication"
                  + (f" (+{len(unauth) - 1} more)" if len(unauth) > 1 else ""),
            summary=(
                "The WebSocket accepted a connection with no credentials and "
                "returned application data (or kept the channel open and accepted "
                "our messages) without rejecting us. Any unauthenticated client "
                "can read the stream and push messages. Authenticate the socket "
                "before serving data — validate a token in the first frame / query "
                "and close on failure."),
            evidence="\n".join(f"  {x['path']}   (source {x['loc']})" for x in unauth[:15]),
            route=f"WS {r['path']}", location=r["loc"],
            reproduction=(f"Open ws(s)://<host>{r['path']} with no auth, send "
                          '{"heimdall":"probe"} and observe data returned / the '
                          "socket staying open."),
            references=[REFS["A01"],
                        "https://portswigger.net/web-security/websockets"],
            tools=["websocat", "Burp Suite"])

    if cswsh:
        r = cswsh[0]
        ctx.finding(
            id="ws-cswsh", owasp="A05", severity="MEDIUM",
            title=f"WebSocket {r['path']} does not validate Origin (CSWSH risk)"
                  + (f" (+{len(cswsh) - 1} more)" if len(cswsh) > 1 else ""),
            summary=(
                "The WebSocket handshake completed with a cross-origin "
                f"Origin ({_ATTACKER_ORIGIN}) — the server enforces no Origin "
                "allow-list. If this socket authenticates via ambient credentials "
                "(a session cookie), a page on any attacker origin can open it as "
                "the victim and read/inject messages (Cross-Site WebSocket "
                "Hijacking). We could not confirm a non-ambient (token-in-message) "
                "auth channel here, so treat CSWSH as exploitable until you verify "
                "the auth mechanism. Fix: validate Origin against an allow-list at "
                "the handshake, and prefer a token in the first frame over cookies."),
            evidence="\n".join(f"  {x['path']}   (source {x['loc']})" for x in cswsh[:15]),
            route=f"WS {r['path']}", location=r["loc"],
            reproduction=(f"Open ws(s)://<host>{r['path']} with header "
                          f"'Origin: {_ATTACKER_ORIGIN}'; the handshake succeeds "
                          "(101). If auth is cookie-based, replay from an attacker "
                          "page to hijack the victim's socket."),
            references=[REFS["A05"],
                        "https://portswigger.net/web-security/websockets/"
                        "cross-site-websocket-hijacking"],
            tools=["websocat", "Burp Suite"])

    if no_origin_dib:
        r = no_origin_dib[0]
        ctx.finding(
            id="ws-no-origin-check", owasp="A05", severity="LOW",
            title=f"WebSocket {r['path']} has no Origin allow-list "
                  "(mitigated by token auth)",
            summary=(
                "The handshake accepts a cross-origin Origin, but the socket "
                "authenticates with a token supplied in the first message / query "
                "(we connected successfully with a valid token that way). Because "
                "that token isn't ambient, a cross-origin page can't supply it, so "
                "CSWSH isn't directly exploitable — this is defense-in-depth. Add "
                "an Origin allow-list at the handshake anyway."),
            evidence="\n".join(f"  {x['path']}   (source {x['loc']})"
                               for x in no_origin_dib[:15]),
            route=f"WS {r['path']}", location=r["loc"],
            references=[REFS["A05"],
                        "https://portswigger.net/web-security/websockets/"
                        "cross-site-websocket-hijacking"])

    if not (unauth or cswsh or no_origin_dib):
        ctx.finding(
            id="ws-safe", owasp="A05", severity="SAFE",
            title="WebSocket endpoints enforce auth and validate Origin",
            summary=(
                f"Probed {len(live)} live WebSocket endpoint(s): each rejected an "
                "unauthenticated connection and/or refused a cross-origin Origin "
                "handshake, consistent with proper auth + Origin validation. "
                "Message-level authorization still warrants manual review."),
            evidence="\n".join(f"  {x['path']}   (source {x['loc']})" for x in live[:15]),
            references=[REFS["A05"],
                        "https://portswigger.net/web-security/websockets"])
