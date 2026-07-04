"""Dependency-free ANSI styling for the CLI — Crimson Report palette.

Colour is auto-disabled when stdout is not a TTY, when ``NO_COLOR`` is set, or
when ``TERM=dumb`` (honours https://no-color.org). ``FORCE_COLOR`` overrides.
Everything degrades to plain text, so piping to a file stays clean.
"""

from __future__ import annotations

import os
import sys

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"

# Crimson Report palette (truecolor RGB), aligned with the HTML report.
ACCENT = (185, 28, 28)      # crimson — chrome, rules, result labels
_SEV_RGB = {
    "CRITICAL": (220, 38, 38),   # bright red (legible on dark terminals)
    "HIGH": (234, 88, 12),       # burnt orange
    "MEDIUM": (202, 138, 4),     # amber
    "LOW": (37, 99, 235),        # blue
    "INFO": (113, 113, 122),     # zinc
    "SAFE": (22, 163, 74),       # green
}

_ENABLED: bool | None = None


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def enabled() -> bool:
    global _ENABLED
    if _ENABLED is None:
        _ENABLED = _supports_color(sys.stdout)
    return _ENABLED


def set_enabled(value: bool) -> None:
    """Force colour on/off (e.g. from a --no-color flag)."""
    global _ENABLED
    _ENABLED = value


def _fg(rgb: tuple[int, int, int]) -> str:
    return f"\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def paint(text: str, rgb: tuple[int, int, int], *, bold: bool = False) -> str:
    if not enabled():
        return text
    return f"{BOLD if bold else ''}{_fg(rgb)}{text}{RESET}"


def accent(text: str, *, bold: bool = True) -> str:
    return paint(text, ACCENT, bold=bold)


def dim(text: str) -> str:
    return f"{DIM}{text}{RESET}" if enabled() else text


def bold(text: str) -> str:
    return f"{BOLD}{text}{RESET}" if enabled() else text


def sev(text: str, severity: str, *, bold: bool = True) -> str:
    return paint(text, _SEV_RGB.get(severity.upper(), _SEV_RGB["INFO"]), bold=bold)


# ── status lines ────────────────────────────────────────────────────────────
# Each kind maps to a coloured glyph; the message stays default-coloured.
_KINDS = {
    "info":   ("»", ACCENT),
    "ok":     ("✓", _SEV_RGB["SAFE"]),
    "warn":   ("!", _SEV_RGB["HIGH"]),
    "err":    ("✗", _SEV_RGB["CRITICAL"]),
    "skip":   ("·", _SEV_RGB["INFO"]),
    "result": ("=", ACCENT),
}


def status(kind: str, msg: str) -> str:
    glyph, rgb = _KINDS.get(kind, _KINDS["info"])
    return f"  {paint(glyph, rgb, bold=True)} {msg}"


def info(msg: str) -> str:
    return status("info", msg)


def ok(msg: str) -> str:
    return status("ok", msg)


def warn(msg: str) -> str:
    return status("warn", msg)


def err(msg: str) -> str:
    return status("err", msg)


def skip(msg: str) -> str:
    return status("skip", dim(msg))


def rule(width: int = 60) -> str:
    return paint("─" * width, ACCENT)


def banner(title: str, subtitle: str = "") -> str:
    """A two-rule crimson banner. Emoji-safe (no box alignment maths)."""
    top = paint("━" * 58, ACCENT)
    head = f"  {bold('🛡  HEIMDALL')}  {dim('·')}  {accent(title)}"
    lines = [top, head]
    if subtitle:
        lines.append(f"     {dim(subtitle)}")
    lines.append(top)
    return "\n".join(lines)
