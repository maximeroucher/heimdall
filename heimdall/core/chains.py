"""Synthesize individual findings into attack chains.

A list of findings undersells risk: the real story is how they compose (a broken
signing key makes every access-control gap moot; a reflected-CORS + never-
expiring token is a durable account takeover). These rules stitch present
findings into narratives an operator can act on, ordered by chain severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_SIGNING = (
    "a02-weak-hs256-secret", "a02-leaked-signing-key", "a02-alg-confusion",
    "a02-alg-none", "a02-kid-injection", "a02-jwk-header", "a02-jku-header",
)
_TOKEN_EXFIL = ("a05-cors-reflected-credentialed", "a05-cors-wildcard-credentialed",
                "a05-cors-reflected", "a02-token-in-query", "a03-xss-reflected")
_TOKEN_DURABLE = ("session-no-exp", "session-long-exp", "session-logout-no-revoke",
                  "session-refresh-reuse", "session-refresh-static")
_ESCALATION = ("a01-self-escalation", "a07-register-mass-assignment")
_XUSER = ("a01-cross-principal-bola", "a01-write-bola", "a01-idor-object-access")


@dataclass
class AttackChain:
    title: str
    severity: str
    steps: list[str]
    finding_ids: list[str] = field(default_factory=list)


def build_chains(findings) -> list[AttackChain]:
    ids = {f.id for f in findings if f.severity != "SAFE"}
    title = {f.id: f.title for f in findings}

    def present(group):
        return [i for i in group if i in ids]

    chains: list[AttackChain] = []

    sign = present(_SIGNING)
    if sign:
        downstream = sorted(i for i in ids if i.startswith("a01-"))
        steps = [
            f"Defeat token signing — {', '.join(title[i] for i in sign[:2])}.",
            "Mint a token with `sub` = any victim/admin and an elevated role/scope claim.",
            "Authenticate as anyone to any endpoint — admin functions and every user's data.",
        ]
        if downstream:
            steps.append("The reported access-control gaps (BOLA/BFLA) become trivially "
                         "exploitable and largely redundant once tokens are forgeable.")
        chains.append(AttackChain(
            "Signing-key compromise → full authentication/authorization takeover",
            "CRITICAL", steps, sign + downstream))

    esc = present(_ESCALATION)
    if esc:
        chains.append(AttackChain(
            "Low-privilege user → administrator", "HIGH",
            [f"Escalate from a normal account — {title[esc[0]]}.",
             "Acquire admin role/flags without any admin approval.",
             "Reach administrative functionality and all users' records."],
            esc + present(("a01-bfla-admin-routes",))))

    xuser = present(_XUSER)
    if xuser:
        chains.append(AttackChain(
            "Any authenticated user → mass cross-user data breach", "HIGH",
            [f"Abuse object access — {', '.join(title[i] for i in xuser)}.",
             "Enumerate victim ids (sequential/UUID) and read or modify their objects.",
             "Exfiltrate or tamper with data across the whole user base at scale."],
            xuser))

    unauth = present(("a01-unauth-secured-routes",))
    if unauth:
        chains.append(AttackChain(
            "Anonymous caller → auth-required data/actions", "HIGH",
            [f"{title[unauth[0]]}.",
             "Call the exposed endpoints with no credentials at all.",
             "Read protected data / trigger protected actions unauthenticated."],
            unauth))

    exfil, durable = present(_TOKEN_EXFIL), present(_TOKEN_DURABLE)
    if exfil and durable:
        chains.append(AttackChain(
            "Token theft → durable account takeover", "HIGH",
            [f"Exfiltrate a session token — {title[exfil[0]]}.",
             f"The token is long-lived / non-revocable — {title[durable[0]]}.",
             "Replay the stolen token indefinitely; logout and rotation don't stop it."],
            exfil + durable))

    ssrf = [i for i in ids if i.startswith("a10-ssrf")]
    if ssrf:
        chains.append(AttackChain(
            "SSRF → internal network / cloud metadata → credentials", "HIGH",
            [f"{title[ssrf[0]]}.",
             "Pivot the server's fetch to 169.254.169.254 / internal services.",
             "Harvest cloud-metadata IAM credentials or reach internal-only APIs."],
            ssrf))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    chains.sort(key=lambda c: order.get(c.severity, 9))
    return chains
