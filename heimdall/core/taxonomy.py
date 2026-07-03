"""OWASP taxonomy, severities, and reference links shared across modules."""

from __future__ import annotations

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "SAFE"]

# Indicative CVSS 3.1 base score per severity band (severity-derived, not a
# per-finding computed vector — a quick at-a-glance magnitude for triage).
CVSS_BAND = {
    "CRITICAL": "9.8", "HIGH": "8.1", "MEDIUM": "5.4",
    "LOW": "3.1", "INFO": "0.0", "SAFE": "—",
}
# SAFE = "we actively tested this and it was NOT exploitable" — kept in the
# report so a reader can tell verified-safe apart from simply-untested.

OWASP_2021 = {
    "A01": "A01:2021 – Broken Access Control",
    "A02": "A02:2021 – Cryptographic Failures",
    "A03": "A03:2021 – Injection",
    "A04": "A04:2021 – Insecure Design",
    "A05": "A05:2021 – Security Misconfiguration",
    "A06": "A06:2021 – Vulnerable and Outdated Components",
    "A07": "A07:2021 – Identification and Authentication Failures",
    "A08": "A08:2021 – Software and Data Integrity Failures",
    "A09": "A09:2021 – Security Logging and Monitoring Failures",
    "A10": "A10:2021 – Server-Side Request Forgery (SSRF)",
}

# Handy canonical references modules can cite by key.
REFS = {
    "A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    # OWASP API Security Top 10 (2023) — Heimdall targets APIs, so cite these too.
    "api3": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "api4": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    "api6": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
    "api9": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    "ps-idor": "https://portswigger.net/web-security/access-control/idor",
    "ps-jwt": "https://portswigger.net/web-security/jwt",
    "ps-sqli": "https://portswigger.net/web-security/sql-injection",
    "ps-cors": "https://portswigger.net/web-security/cors",
    "ps-massassign": "https://portswigger.net/web-security/api-testing/server-side-parameter-pollution",
    "cheat-authz": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
}
