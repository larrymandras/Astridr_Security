"""PII filter — detects and optionally redacts personally identifiable information.

Layer 1 of the security pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

logger = structlog.get_logger()


# ─── Action modes ─────────────────────────────────────────────────


class PIIAction(str, Enum):
    DETECT = "detect"
    REDACT = "redact"
    BLOCK = "block"


# ─── Detection dataclass ─────────────────────────────────────────


@dataclass
class PIIDetection:
    pii_type: str
    matched_text: str
    start: int
    end: int


# ─── Patterns ─────────────────────────────────────────────────────

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("ip_address", re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )),
]


# ─── Public API ───────────────────────────────────────────────────


def detect(text: str) -> list[PIIDetection]:
    """Scan *text* and return all PII detections."""
    detections: list[PIIDetection] = []
    for pii_type, pattern in _PII_PATTERNS:
        for match in pattern.finditer(text):
            detections.append(
                PIIDetection(
                    pii_type=pii_type,
                    matched_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return detections


def redact_pii(text: str) -> str:
    """Replace all detected PII with ``[PII:type]`` placeholders."""
    detections = detect(text)
    if not detections:
        return text

    detections.sort(key=lambda d: d.start, reverse=True)
    result = text
    for det in detections:
        placeholder = f"[PII:{det.pii_type}]"
        result = result[: det.start] + placeholder + result[det.end :]
    return result


# ─── SecurityLayer implementation ─────────────────────────────────


class PIIFilterLayer(SecurityLayer):
    """Layer 1 — detect and optionally redact PII from messages."""

    name: str = "pii_filter"

    def __init__(
        self,
        action: PIIAction = PIIAction.REDACT,
        passthrough_profiles: set[str] | None = None,
    ) -> None:
        self._action = action
        self._passthrough_profiles = passthrough_profiles or set()

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        return self._process(message, context)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        return self._process(message, context)

    def _process(self, message: str, context: SecurityContext) -> SecurityResult:
        # Passthrough profiles skip PII filtering
        if context.profile_id in self._passthrough_profiles:
            return SecurityResult(allowed=True, message=message)

        detections = detect(message)
        if not detections:
            return SecurityResult(allowed=True, message=message)

        types_found = list({d.pii_type for d in detections})
        events: list[dict] = [
            {
                "layer": self.name,
                "severity": "warning",
                "action": self._action.value,
                "profileId": context.profile_id,
                "details": {
                    "types": types_found,
                    "count": len(detections),
                },
            }
        ]

        if self._action == PIIAction.DETECT:
            return SecurityResult(allowed=True, message=message, events=events)

        if self._action == PIIAction.BLOCK:
            return SecurityResult(
                allowed=False,
                message=message,
                events=events,
                blocked_reason=f"PII detected: {', '.join(types_found)}",
            )

        # REDACT
        redacted = redact_pii(message)
        return SecurityResult(allowed=True, message=redacted, events=events)
