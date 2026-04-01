"""Injection defense — detects prompt injection and obfuscation attacks.

Layer 3 of the security pipeline.  Analyses both inbound and outbound
messages for:

* Known injection phrases (e.g. "ignore previous instructions")
* Delimiter injection (fake XML/JSON tags)
* Unicode normalisation attacks (zero-width spaces, RTL overrides, homoglyphs)
* Obfuscated commands (Base64-encoded shell, hex/octal escapes, variable
  expansion tricks)
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

logger = structlog.get_logger()


# ─── Severity ─────────────────────────────────────────────────────


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# ─── Detection result ─────────────────────────────────────────────


@dataclass
class InjectionDetection:
    category: str  # e.g. "known_phrase", "delimiter", "unicode", "obfuscated"
    detail: str
    severity: Severity


# ─── Known injection phrases ──────────────────────────────────────

_INJECTION_PHRASES: list[tuple[re.Pattern[str], Severity]] = [
    (re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I), Severity.CRITICAL),
    (re.compile(r"you\s+are\s+now", re.I), Severity.CRITICAL),
    (re.compile(r"system\s+prompt", re.I), Severity.WARNING),
    (re.compile(r"reveal\s+your", re.I), Severity.WARNING),
    (re.compile(r"forget\s+everything", re.I), Severity.CRITICAL),
    (re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|above)", re.I), Severity.CRITICAL),
    (re.compile(r"new\s+instructions?\s*:", re.I), Severity.CRITICAL),
    (re.compile(r"act\s+as\s+(?:a\s+)?(?:different|new)", re.I), Severity.WARNING),
    (re.compile(r"pretend\s+(?:you(?:'re|\s+are)\s+)(?:a\s+)?", re.I), Severity.WARNING),
    (re.compile(r"do\s+not\s+follow\s+(?:any|your)\s+(?:rules|guidelines)", re.I), Severity.CRITICAL),
]

# ─── Delimiter injection patterns ────────────────────────────────

_DELIMITER_PATTERNS: list[re.Pattern[str]] = [
    # Fake XML-ish tags that look like system instructions
    re.compile(r"<\s*/?(?:system|instruction|prompt|role|context|admin)\s*>", re.I),
    # JSON-ish injection
    re.compile(r'\{\s*"(?:role|system|instruction)"\s*:', re.I),
    # Markdown heading used to fake instructions
    re.compile(r"^#{1,3}\s*(?:system|instruction|new\s+rules)", re.I | re.M),
]

# ─── Unicode suspicious characters ───────────────────────────────

# Zero-width and bidi control characters
_SUSPICIOUS_CODEPOINTS: set[int] = {
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x200E,  # left-to-right mark
    0x200F,  # right-to-left mark
    0x202A,  # left-to-right embedding
    0x202B,  # right-to-left embedding
    0x202C,  # pop directional formatting
    0x202D,  # left-to-right override
    0x202E,  # right-to-left override
    0x2060,  # word joiner
    0x2061,  # function application
    0x2062,  # invisible times
    0x2063,  # invisible separator
    0x2064,  # invisible plus
    0xFEFF,  # byte order mark / zero-width no-break space
}

# Common homoglyph mappings (Cyrillic / Greek -> Latin)
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041D": "H", "\u041A": "K", "\u041C": "M", "\u041E": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
}

# ─── Obfuscation patterns ────────────────────────────────────────

_BASE64_CMD_RE = re.compile(
    r"(?:echo|printf)\s+['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*(?:base64\s+-d|b64decode)",
    re.I,
)

_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_OCTAL_ESCAPE_RE = re.compile(r"(?:\\[0-7]{3}){4,}")
_VAR_EXPANSION_RE = re.compile(r"\$\{[^}]*\}\s*\$\{[^}]*\}", re.I)


# ─── Public API ───────────────────────────────────────────────────


def analyse(text: str) -> list[InjectionDetection]:
    """Analyse *text* for injection attempts. Returns all detections."""
    results: list[InjectionDetection] = []

    # 1) Known phrases
    for pattern, severity in _INJECTION_PHRASES:
        if pattern.search(text):
            results.append(
                InjectionDetection(
                    category="known_phrase",
                    detail=pattern.pattern,
                    severity=severity,
                )
            )

    # 2) Delimiter injection
    for pattern in _DELIMITER_PATTERNS:
        if pattern.search(text):
            results.append(
                InjectionDetection(
                    category="delimiter",
                    detail=pattern.pattern,
                    severity=Severity.WARNING,
                )
            )

    # 3) Unicode tricks
    results.extend(_check_unicode(text))

    # 4) Obfuscated commands
    results.extend(_check_obfuscation(text))

    return results


def normalise_unicode(text: str) -> str:
    """Strip zero-width / bidi characters and replace homoglyphs."""
    cleaned = "".join(ch for ch in text if ord(ch) not in _SUSPICIOUS_CODEPOINTS)
    cleaned = "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in cleaned)
    cleaned = unicodedata.normalize("NFKC", cleaned)
    return cleaned


def max_severity(detections: list[InjectionDetection]) -> Severity | None:
    """Return the highest severity found, or None if no detections."""
    if not detections:
        return None
    order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
    return max(detections, key=lambda d: order[d.severity]).severity


# ─── Internal helpers ─────────────────────────────────────────────


def _check_unicode(text: str) -> list[InjectionDetection]:
    detections: list[InjectionDetection] = []

    # Zero-width / bidi
    suspicious_found = [ch for ch in text if ord(ch) in _SUSPICIOUS_CODEPOINTS]
    if suspicious_found:
        codepoints = [f"U+{ord(c):04X}" for c in set(suspicious_found)]
        detections.append(
            InjectionDetection(
                category="unicode",
                detail=f"suspicious codepoints: {', '.join(codepoints)}",
                severity=Severity.WARNING,
            )
        )

    # Homoglyphs
    homoglyphs_found = [ch for ch in text if ch in _HOMOGLYPH_MAP]
    if homoglyphs_found:
        detections.append(
            InjectionDetection(
                category="unicode",
                detail=f"homoglyphs detected ({len(homoglyphs_found)} chars)",
                severity=Severity.WARNING,
            )
        )

    return detections


def _check_obfuscation(text: str) -> list[InjectionDetection]:
    detections: list[InjectionDetection] = []

    # Base64-encoded commands
    for m in _BASE64_CMD_RE.finditer(text):
        b64_payload = m.group(1)
        try:
            decoded = base64.b64decode(b64_payload).decode("utf-8", errors="replace")
            detections.append(
                InjectionDetection(
                    category="obfuscated",
                    detail=f"base64 command: {decoded[:80]}",
                    severity=Severity.CRITICAL,
                )
            )
        except Exception:
            detections.append(
                InjectionDetection(
                    category="obfuscated",
                    detail="base64 payload (decode failed)",
                    severity=Severity.WARNING,
                )
            )

    # Hex escapes
    if _HEX_ESCAPE_RE.search(text):
        detections.append(
            InjectionDetection(
                category="obfuscated",
                detail="hex escape sequences",
                severity=Severity.WARNING,
            )
        )

    # Octal escapes
    if _OCTAL_ESCAPE_RE.search(text):
        detections.append(
            InjectionDetection(
                category="obfuscated",
                detail="octal escape sequences",
                severity=Severity.WARNING,
            )
        )

    # Variable expansion chains
    if _VAR_EXPANSION_RE.search(text):
        detections.append(
            InjectionDetection(
                category="obfuscated",
                detail="variable expansion chains",
                severity=Severity.WARNING,
            )
        )

    return detections


# ─── SecurityLayer implementation ─────────────────────────────────


class InjectionDefenseLayer(SecurityLayer):
    """Layer 3 — detect and block prompt-injection attacks."""

    name: str = "injection_defense"

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        # Normalise first so homoglyph tricks don't bypass phrase detection
        normalised = normalise_unicode(message)
        detections = analyse(normalised)
        # Also scan the raw text for unicode-specific detections
        detections.extend(_check_unicode(message))
        # Deduplicate
        seen: set[tuple[str, str]] = set()
        unique: list[InjectionDetection] = []
        for d in detections:
            key = (d.category, d.detail)
            if key not in seen:
                seen.add(key)
                unique.append(d)
        detections = unique

        severity = max_severity(detections)
        events: list[dict] = []

        if detections:
            events.append(
                {
                    "layer": self.name,
                    "severity": severity.value if severity else "info",
                    "action": "blocked" if severity == Severity.CRITICAL else "flagged",
                    "profileId": context.profile_id,
                    "details": {
                        "detections": [
                            {"category": d.category, "detail": d.detail, "severity": d.severity.value}
                            for d in detections
                        ],
                    },
                }
            )

        if severity == Severity.CRITICAL:
            return SecurityResult(
                allowed=False,
                message=message,
                events=events,
                blocked_reason="prompt injection detected",
            )

        return SecurityResult(allowed=True, message=message, events=events)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        # Outbound injection checks are lighter — mainly looking for
        # the model trying to emit injection payloads back to the user.
        detections = analyse(message)
        severity = max_severity(detections)
        events: list[dict] = []

        if detections:
            events.append(
                {
                    "layer": self.name,
                    "severity": severity.value if severity else "info",
                    "action": "flagged",
                    "profileId": context.profile_id,
                    "details": {
                        "detections": [
                            {"category": d.category, "detail": d.detail, "severity": d.severity.value}
                            for d in detections
                        ],
                    },
                }
            )

        # Outbound is never blocked by injection defense — only flagged.
        return SecurityResult(allowed=True, message=message, events=events)
