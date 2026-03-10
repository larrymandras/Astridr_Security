"""Sensitive Action — catch semantic intent patterns for credential access.

Layer 5 of the security pipeline.

This differs from BlocklistLayer (Layer 4): Blocklist catches literal paths
(``.env``, ``.ssh/``) and commands (``rm -rf``).  Sensitive Action catches
intent patterns like "read my API keys", "what's the database password",
"access the production credentials".

Design: Inbound sensitive actions are **flagged** (allowed + warning event),
not blocked outright — these are heuristic and may have false positives.
Outbound credential leaks ARE blocked.
"""

from __future__ import annotations

import re

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

logger = structlog.get_logger()

# Semantic intent patterns (not literal paths)
_INBOUND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:show|read|get|access|retrieve|display|give|tell|reveal)\b"
            r".*\b(?:passwords?|passwd|secrets?|credentials?|api.?keys?|private.?keys?|tokens?)\b",
            re.IGNORECASE,
        ),
        "credential access attempt",
    ),
    (
        re.compile(
            r"\b(?:dump|export|backup)\b"
            r".*\b(?:database|db|tables?|users?)\b",
            re.IGNORECASE,
        ),
        "database dump attempt",
    ),
    (
        re.compile(
            r"\b(?:modify|change|update|set)\b"
            r".*\b(?:permissions?|chmod|chown|sudo|admin)\b",
            re.IGNORECASE,
        ),
        "privilege escalation attempt",
    ),
    (
        re.compile(
            r"\b(?:connect|ssh|rdp|telnet)\b"
            r".*\b(?:production|prod|servers?|root)\b",
            re.IGNORECASE,
        ),
        "production access attempt",
    ),
]

# Outbound patterns — agent response leaking credentials
_OUTBOUND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:password|passwd)\s+(?:is|=|:)\s+\S+",
            re.IGNORECASE,
        ),
        "password leak",
    ),
    (
        re.compile(
            r"\b(?:api.?key|secret.?key|private.?key|token)\s+(?:is|=|:)\s+\S+",
            re.IGNORECASE,
        ),
        "credential leak",
    ),
]


class SensitiveActionLayer(SecurityLayer):
    """Layer 5 — flag sensitive action intents, block credential leaks."""

    name: str = "sensitive_action"

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        events: list[dict] = []
        for pattern, reason in _INBOUND_PATTERNS:
            if pattern.search(message):
                events.append({
                    "layer": self.name,
                    "severity": "warning",
                    "action": "flagged",
                    "profileId": context.profile_id,
                    "details": {"reason": reason},
                })
                logger.warning(
                    "sensitive_action.flagged",
                    reason=reason,
                    profile_id=context.profile_id,
                )
                break  # One flag per message is sufficient
        return SecurityResult(allowed=True, message=message, events=events)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        for pattern, reason in _OUTBOUND_PATTERNS:
            if pattern.search(message):
                return SecurityResult(
                    allowed=False,
                    message=message,
                    events=[{
                        "layer": self.name,
                        "severity": "critical",
                        "action": "blocked",
                        "profileId": context.profile_id,
                        "details": {"reason": reason},
                    }],
                    blocked_reason=reason,
                )
        return SecurityResult(allowed=True, message=message)
