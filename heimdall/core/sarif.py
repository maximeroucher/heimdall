"""SARIF 2.1.0 output so Heimdall results flow into code-scanning dashboards.

GitHub / GitLab / Azure DevOps ingest SARIF to render findings, set severities
(via ``security-severity``) and de-duplicate across runs (``partialFingerprints``).
Real findings are emitted as ``kind: fail``; TESTED-SAFE ones as ``kind: pass``
so a reader can see what was actively verified, not just what failed.
"""

from __future__ import annotations

from .taxonomy import CVSS_BAND, OWASP_2021

_LEVEL = {
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
    "LOW": "note", "INFO": "note", "SAFE": "note",
}


def to_sarif(findings, meta: dict) -> dict:
    # One rule per distinct finding id (its class), with GitHub severity metadata.
    rules: dict[str, dict] = {}
    for f in findings:
        if f.id in rules:
            continue
        rules[f.id] = {
            "id": f.id,
            "name": "".join(w.capitalize() for w in f.id.split("-")),
            "shortDescription": {"text": f.title[:120]},
            "fullDescription": {"text": f.summary[:900]},
            "helpUri": (f.references[0] if f.references else
                        "https://owasp.org/Top10/"),
            "defaultConfiguration": {"level": _LEVEL[f.severity]},
            "properties": {
                "tags": ["security", f.owasp, OWASP_2021[f.owasp]],
                "security-severity": CVSS_BAND[f.severity]
                if f.severity != "SAFE" else "0.0",
                "owasp": f.owasp,
            },
        }

    results = []
    for f in findings:
        text = f.summary
        if f.evidence:
            text += "\n\nEvidence:\n" + f.evidence.strip()
        if f.reproduction:
            text += "\n\nReproduction:\n" + f.reproduction.strip()
        results.append({
            "ruleId": f.id,
            "level": _LEVEL[f.severity],
            "kind": "pass" if f.severity == "SAFE" else "fail",
            "message": {"text": text},
            "locations": [{
                "logicalLocations": [{
                    "name": meta.get("base_url", "target"),
                    "kind": "resource",
                }],
            }],
            "partialFingerprints": {"heimdallFindingId/v1": f.id},
            "properties": {
                "severity": f.severity,
                "owasp": f.owasp,
                "cvss": CVSS_BAND[f.severity],
                "module": f.module,
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Heimdall",
                "informationUri": "https://github.com/maximeroucher/heimdall",
                "version": meta.get("version", "0.1.0"),
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"heimdall/{meta.get('date', '')}"},
            "results": results,
        }],
    }
