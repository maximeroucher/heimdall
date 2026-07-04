"""Chains, SARIF, guardrail, and report writing."""

import json
import os

import pytest

from heimdall.core.chains import build_chains
from heimdall.core.findings import Finding, write_reports
from heimdall.core.guardrail import assert_target_allowed, is_loopback
from heimdall.core.sarif import to_sarif


def _fs():
    return [
        Finding("a02-weak-hs256-secret", "A02", "Guessable JWT secret", "CRITICAL", "x"),
        Finding("a01-cross-principal-bola", "A01", "Cross-user BOLA", "HIGH", "x"),
        Finding("a01-self-escalation", "A01", "Self escalation", "HIGH", "x"),
        Finding("a02-alg-none", "A02", "alg:none rejected", "SAFE", "x"),
    ]


def test_finding_validation():
    with pytest.raises(ValueError):
        Finding("id", "A02", "t", "NOPE", "s")
    with pytest.raises(ValueError):
        Finding("id", "A99", "t", "HIGH", "s")


def test_build_chains_signing_and_escalation():
    chains = build_chains(_fs())
    titles = [c.title for c in chains]
    assert any("Signing-key compromise" in t for t in titles)
    assert any("administrator" in t for t in titles)          # self-escalation chain
    assert any("cross-user data breach" in t for t in titles)  # BOLA chain
    # highest severity first
    assert chains[0].severity == "CRITICAL"
    # signing chain references the downstream a01 findings
    sign = next(c for c in chains if "Signing-key" in c.title)
    assert "a01-cross-principal-bola" in sign.finding_ids


def test_build_chains_empty_when_no_real_findings():
    assert build_chains([Finding("a02-alg-none", "A02", "t", "SAFE", "s")]) == []


def test_to_sarif_structure_and_levels():
    s = to_sarif(_fs(), {"base_url": "http://127.0.0.1", "date": "2026-07-03"})
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "Heimdall"
    assert len(run["tool"]["driver"]["rules"]) == 4
    results = run["results"]
    crit = next(r for r in results if r["ruleId"] == "a02-weak-hs256-secret")
    assert crit["level"] == "error" and crit["kind"] == "fail"
    safe = next(r for r in results if r["ruleId"] == "a02-alg-none")
    assert safe["kind"] == "pass"
    # GitHub security-severity present on the rule
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "a02-weak-hs256-secret")
    assert rule["properties"]["security-severity"] == "9.8"


def test_is_loopback():
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("::1") is True
    assert is_loopback("8.8.8.8") is False


def test_guardrail_blocks_non_loopback():
    with pytest.raises(SystemExit):
        assert_target_allowed("http://example.com", authorized=False)
    # authorized override is allowed
    assert_target_allowed("http://example.com", authorized=True)
    # loopback always allowed
    assert_target_allowed("http://127.0.0.1:8000", authorized=False)


def test_write_reports_emits_all_artifacts(tmp_path):
    paths = write_reports(_fs(), str(tmp_path),
                          {"app_name": "Demo", "base_url": "http://127.0.0.1", "date": "d"})
    assert len(paths) == 4
    for name in ("findings.json", "REPORT.md", "REPORT.html", "findings.sarif"):
        assert os.path.exists(os.path.join(tmp_path, name))
    md = open(os.path.join(tmp_path, "REPORT.md")).read()
    assert "9.8" in md and "Attack chains" in md          # CVSS + chains rendered
    sarif = json.load(open(os.path.join(tmp_path, "findings.sarif")))
    assert sarif["runs"][0]["results"]


def test_html_report_structure_and_summary(tmp_path):
    write_reports(_fs(), str(tmp_path),
                  {"app_name": "Demo", "base_url": "http://127.0.0.1", "date": "d",
                   "route_count": 12, "principals": ["admin", "user"]})
    html = open(os.path.join(tmp_path, "REPORT.html")).read()
    assert html.lstrip().startswith("<!doctype html>")
    assert "Demo" in html and "http://127.0.0.1" in html
    # interactive severity filter + copy handlers shipped
    assert "sevFilter" in html and "copyPre" in html
    # executive-summary cards + at-a-glance anchors
    assert 'data-sev="CRITICAL"' in html and 'href="#f1"' in html
    # attack-chains section rendered from the same findings
    assert "Attack chains" in html


def test_html_report_autoescapes_findings(tmp_path):
    # a finding carrying markup must not break the page or inject script
    evil = Finding("a03-xss", "A03", "Stored <script>alert(1)</script>", "HIGH",
                   "Payload persisted: <img src=x onerror=alert(1)>")
    write_reports([evil], str(tmp_path),
                  {"app_name": "Demo", "base_url": "http://127.0.0.1", "date": "d"})
    html = open(os.path.join(tmp_path, "REPORT.html")).read()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "onerror=alert(1)&gt;" in html
