"""A05 — Unrestricted file upload.

FastAPI's ``UploadFile`` / multipart form is a first-class feature, and the
classic PortSwigger lab applies directly: an endpoint that stores an uploaded
file without validating its type/extension/content lets an attacker plant
active content. On a Python/JSON backend the realistic wins are **stored XSS**
(upload an ``.html`` / ``.svg`` that's later served with a renderable
Content-Type) and **content-type / extension bypass** (server trusts the
client-supplied MIME or the extension); a web shell only matters if something
downstream executes the file.

  1. Discovery: multipart/form-data routes with a binary (file) field — read
     straight from the OpenAPI request body, no traffic.
  2. Probing (FULL mode — it writes): send a benign image control, then a set of
     dangerous payloads (HTML/SVG script, a PHP stub, a double-extension, a
     content-type spoof, a path-traversal filename). If the server ACCEPTS a
     dangerous type it's already a finding; if the response hands back a URL to
     the stored file, we fetch it and check whether our script comes back with a
     renderable Content-Type — that upgrades it to a *confirmed* stored XSS.

Everything the module uploads is a harmless canary; nothing is executed.
"""

from __future__ import annotations

import os
import re

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

_CANARY = "heimdall31337"
_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32  # minimal PNG magic + padding
_SVG = (f'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
        f'<script>/*{_CANARY}*/</script></svg>').encode()
_HTML = f"<!doctype html><script>/*{_CANARY}*/</script>".encode()
_PHP = f"<?php echo '{_CANARY}'; ?>".encode()

# (filename, bytes, content-type, tag) — the tag classifies the risk if accepted.
def _payload_files() -> list[tuple]:
    return [
        ("heimdall.png", _PNG, "image/png", "control"),
        ("heimdall.html", _HTML, "text/html", "html"),
        ("heimdall.svg", _SVG, "image/svg+xml", "svg"),
        # content-type spoof: dangerous body, image MIME + image-ish name.
        ("heimdall_spoof.png", _HTML, "image/png", "spoof-ct"),
        # double extension — bypasses naive endswith('.png') checks.
        ("heimdall.png.html", _HTML, "text/html", "double-ext"),
        ("heimdall.phtml", _PHP, "application/octet-stream", "php"),
        # path traversal in the stored filename.
        ("../../heimdall_trav.html", _HTML, "text/html", "path-traversal"),
    ]


_MAX_ROUTES = 12
_RENDERABLE = ("text/html", "image/svg+xml", "application/xhtml")


@module("file-upload", "Unrestricted File Upload", destructive=True)
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    routes = _upload_routes(ctx)
    if not routes:
        ctx.note("file-upload: no multipart file-upload endpoints in the surface")
        return
    if ctx.safe:
        ctx.note(f"file-upload: {len(routes)} upload endpoint(s) found — skipped "
                 "(writes; FULL mode only)")
        return

    static_prefixes = _static_mount_prefixes(ctx)
    confirmed: list[dict] = []
    accepted: list[dict] = []
    probed = 0
    for route, file_field, form_fields in routes[:_MAX_ROUTES]:
        probed += 1
        _probe_route(ctx, route, file_field, form_fields, token, confirmed, accepted,
                     static_prefixes)

    ctx.note(f"file-upload: probed {probed} endpoint(s); {len(confirmed)} confirmed "
             f"served-back active content, {len(accepted)} accepted a dangerous type")
    if confirmed:
        _report(ctx, confirmed, accepted, confirmed_stored=True)
    elif accepted:
        _report(ctx, confirmed, accepted, confirmed_stored=False)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery ────────────────────────────────────────────────────────────────

def _upload_routes(ctx: Context) -> list[tuple]:
    """Return (route, file_field, [other_form_fields]) for multipart uploads."""
    out = []
    for r in ctx.routes:
        if r.method not in ("POST", "PUT", "PATCH"):
            continue
        content = (r.raw.get("requestBody", {}) or {}).get("content", {})
        if "multipart/form-data" not in content:
            continue
        props = (r.body_schema or {}).get("properties", {}) or {}
        file_field = None
        form_fields = []
        for name, sch in props.items():
            if isinstance(sch, dict) and sch.get("format") == "binary":
                file_field = file_field or name
            else:
                form_fields.append(name)
        # Fallback: a multipart body with no declared binary prop still often
        # takes a file under a conventional field name.
        if not file_field:
            file_field = next((n for n in ("file", "upload", "image", "photo")
                               if n in props), "file")
        out.append((r, file_field, form_fields))
    return out


# ── probing ──────────────────────────────────────────────────────────────────

def _probe_route(ctx, route, file_field, form_fields, token, confirmed, accepted,
                 static_prefixes):
    path = route.fill_path({p: "1" for p in route.path_params})
    data = {f: _CANARY for f in form_fields}
    for filename, blob, ctype, tag in _payload_files():
        files = {file_field: (filename, blob, ctype)}
        try:
            resp = ctx.request(route.method, path, token=token, files=files,
                               data=data, timeout=15, retry_429=False)
        except requests.RequestException:
            continue
        if resp.status_code >= 400 or tag == "control":
            continue
        # Server accepted a dangerous upload.
        rec = {"route": route, "tag": tag, "filename": filename,
               "ctype": ctype, "status": resp.status_code}
        # Try to confirm it's served back as active content.
        served = _confirm_served(ctx, resp, token, filename, static_prefixes)
        if served:
            rec["served"] = served
            confirmed.append(rec)
        else:
            accepted.append(rec)


# static-file mount prefixes an upload is commonly served back from — an uploaded
# .html/.svg served here with a renderable Content-Type is stored XSS.
_COMMON_STATIC = ("/static", "/uploads", "/upload", "/media", "/files", "/file",
                  "/public", "/assets", "/img", "/images", "/storage", "")
_STATIC_MOUNT_RE = re.compile(
    r"""\.mount\(\s*["']([^"']+)["'][^)]*StaticFiles""", re.IGNORECASE | re.DOTALL)


def _static_mount_prefixes(ctx: Context) -> list[str]:
    """Where uploads might be served from — StaticFiles mounts detected in source
    (`app.mount("/static", StaticFiles(...))`) plus common conventions."""
    prefixes = list(_COMMON_STATIC)
    src = getattr(ctx.profile, "source_path", None)
    if src and os.path.isdir(src):
        found = 0
        for dp, dn, fn in os.walk(src):
            dn[:] = [d for d in dn if not d.startswith(".") and d not in
                     ("node_modules", "venv", ".venv", "__pycache__", "site-packages")]
            for f in fn:
                if not f.endswith(".py"):
                    continue
                try:
                    txt = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for m in _STATIC_MOUNT_RE.finditer(txt):
                    p = m.group(1).rstrip("/")
                    if p and p not in prefixes:
                        prefixes.insert(0, p)   # source-detected mount wins
                found += 1
                if found >= 400:
                    return prefixes
    return prefixes


_URL_RE = re.compile(r'https?://[^\s"\'<>]+|/[A-Za-z0-9_\-./]+\.[A-Za-z0-9]{2,5}')


def _confirm_served(ctx: Context, upload_resp, token, filename: str = "",
                    static_prefixes: list | None = None) -> dict | None:
    """If the stored file is reachable, fetch it and check whether our canary
    comes back with a renderable Content-Type (stored XSS). Candidate URLs come
    from the upload response body AND from the stored filename joined to common /
    source-detected StaticFiles mount prefixes."""
    try:
        body = upload_resp.text or ""
    except Exception:  # pragma: no cover - defensive
        return None
    cand = [m for m in _URL_RE.findall(body)
            if any(h in m.lower() for h in ("heimdall", "upload", "file", "photo", "media"))]
    # a bare filename in the response (`{"filename": "x.html"}`) served under a
    # static mount — try each candidate prefix.
    base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if base:
        for pfx in (static_prefixes or _COMMON_STATIC):
            cand.append(f"{pfx}/{base}")
    seen = set()
    for url in [c for c in cand if not (c in seen or seen.add(c))][:14]:
        try:
            path = url if url.startswith("http") else url
            r = ctx.get(path, token=token, timeout=10, retry_429=False)
        except requests.RequestException:
            continue
        ct = r.headers.get("Content-Type", "").lower()
        if r.status_code < 400 and _CANARY in (r.text or "") \
                and any(t in ct for t in _RENDERABLE):
            return {"url": url, "ctype": ct}
    return None


# ── findings ─────────────────────────────────────────────────────────────────

def _report(ctx, confirmed, accepted, *, confirmed_stored: bool) -> None:
    all_recs = confirmed + accepted
    lead = (confirmed or accepted)[0]
    r = lead["route"]
    lines = []
    for c in all_recs[:15]:
        cr = c["route"]
        extra = (f"  -> served back as active content at {c['served']['url']} "
                 f"({c['served']['ctype']})" if c.get("served") else "")
        lines.append(f"  {cr.method} {cr.path}  accepted {c['tag']} "
                     f"({c['filename']}, sent {c['ctype']}) -> HTTP {c['status']}{extra}")
    severity = "HIGH" if confirmed_stored else "MEDIUM"
    ctx.finding(
        id="a05-unrestricted-file-upload",
        owasp="A05", severity=severity,
        title=(f"Unrestricted file upload on {r.method} {r.path}"
               + (" (stored XSS confirmed)" if confirmed_stored else "")
               + (f" (+{len(all_recs) - 1} more)" if len(all_recs) > 1 else "")),
        summary=(
            "The upload endpoint stored a file whose type/extension/content it "
            "should have rejected. "
            + ("The stored file is served back with a renderable Content-Type and "
               "our injected script survives intact — a stored XSS: any user who "
               "views it runs attacker JavaScript in the app's origin (session/"
               "token theft). "
               if confirmed_stored else
               "A dangerous type (HTML/SVG/script or a content-type/extension "
               "bypass) was accepted; if the file is ever served with a "
               "renderable Content-Type this is stored XSS, and if anything "
               "downstream executes it, code execution. Confirm how the stored "
               "file is served. ")
            + "Validate the real content (magic bytes), pin an allow-list of "
            "extensions, store outside the web root, and serve with "
            "Content-Disposition: attachment + a non-renderable Content-Type."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=(f"{r.method} {r.path}  multipart file '{lead['filename']}' "
                 f"(Content-Type {lead['ctype']})"),
        reproduction=(
            f"Upload a file named '{lead['filename']}' with body "
            f"'<script>…</script>' to {r.method} {r.path}"
            + (f", then GET {lead['served']['url']} and observe it served as "
               f"{lead['served']['ctype']} with the script intact."
               if lead.get("served")
               else " and trace where/how the stored file is later served.")
        ),
        references=[REFS["A05"],
                    "https://portswigger.net/web-security/file-upload",
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "File_Upload_Cheat_Sheet.html"],
        tools=["Burp Suite", "curl -F"],
    )


def _report_safe(ctx: Context, probed: int) -> None:
    ctx.finding(
        id="a05-file-upload-safe",
        owasp="A05", severity="SAFE",
        title="File-upload endpoints rejected dangerous types",
        summary=(
            f"Uploaded HTML/SVG/script, content-type-spoofed, double-extension and "
            f"path-traversal-named files to {probed} multipart endpoint(s); all "
            "dangerous variants were rejected (only the benign image control was "
            "accepted), consistent with content/extension validation. If uploads "
            "are served from a user-facing path, still confirm the Content-Type "
            "and Content-Disposition used to serve them."
        ),
        references=[REFS["A05"],
                    "https://portswigger.net/web-security/file-upload"],
    )
