"""Secret scanner — detects and redacts secrets, API keys, and credentials.

Used by both the inbound (user messages) and outbound (tool outputs) paths
of the security pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

logger = structlog.get_logger()


# ─── Detection dataclass ───────────────────────────────────────────────


@dataclass
class Detection:
    """A single secret detection."""

    secret_type: str
    matched_text: str
    start: int
    end: int


# ─── Patterns ─────────────────────────────────────────────────────────

# Each tuple: (secret_type, compiled regex)
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # API keys (Stripe-style sk_/pk_, OpenAI-style sk-)
    ("api_key", re.compile(r"\b(?:sk|pk)[-_](?:live|test|prod)?[-_]?[A-Za-z0-9]{20,}\b")),
    # AWS access key IDs
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS secret access keys (40-char base64)
    ("aws_secret", re.compile(r"(?<=['\"]\s=:])[A-Za-z0-9/+=]{40}(?=['\"]\s,\n]|$)")),
    # JWTs (three base64url sections separated by dots)
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    # Generic passwords in config-style text
    ("password", re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token)[\s]*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"
    )),
    # Private key blocks
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )),
    # Emails
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    # Phone numbers (international / US)
    ("phone", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")),
    # SSNs
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


# ─── Public helpers ───────────────────────────────────────────────────


def scan(text: str) -> list[Detection]:
    """Return all secret detections in *text*."""
    detections: list[Detection] = []
    for secret_type, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            detections.append(
                Detection(
                    secret_type=secret_type,
                    matched_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return detections


def redact(text: str) -> str:
    """Replace all detected secrets with ``[REDACTED:type]`` placeholders."""
    detections = scan(text)
    if not detections:
        return text

    # Sort by start position descending so replacements don't shift indices
    detections.sort(key=lambda d: d.start, reverse=True)
    result = text
    for det in detections:
        placeholder = f"[REDACTED:{det.secret_type}]"
        result = result[: det.start] + placeholder + result[det.end :]
    return result


# ─── SecurityLayer implementation ─────────────────────────────────────


class SecretRedactorLayer(SecurityLayer):
    """Layer 7 — redact secrets from outbound messages and flag inbound."""

    name: str = "secret_redactor"

    # Secrets in outbound messages are always redacted.
    # Secrets in inbound messages are logged but allowed through (the user
    # might be providing credentials intentionally).

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        detections = scan(message)
        events: list[dict] = []
        if detections:
            types_found = list({d.secret_type for d in detections})
            events.append(
                {
                    "layer": self.name,
                    "severity": "warning",
                    "action": "flagged",
                    "profileId": context.profile_id,
                    "details": {
                        "types": types_found,
                        "count": len(detections),
                    },
                }
            )
            logger.warning(
                "secret_scanner.inbound_detected",
                types=types_found,
                count=len(detections),
                profile_id=context.profile_id,
            )
        return SecurityResult(allowed=True, message=message, events=events)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        detections = scan(message)
        events: list[dict] = []
        if detections:
            types_found = list({d.secret_type for d in detections})
            redacted = redact(message)
            events.append(
                {
                    "layer": self.name,
                    "severity": "warning",
                    "action": "redacted",
                    "profileId": context.profile_id,
                    "details": {
                        "types": types_found,
                        "count": len(detections),
                    },
                }
            )
            logger.warning(
                "secret_scanner.outbound_redacted",
                types=types_found,
                count=len(detections),
                profile_id=context.profile_id,
            )
            return SecurityResult(allowed=True, message=redacted, events=events)
        return SecurityResult(allowed=True, message=message, events=events)
