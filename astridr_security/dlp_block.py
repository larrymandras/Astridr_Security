"""DLP Block — prevent cross-profile data leakage at the message level.

Layer 2 of the security pipeline.

Profiles are ``personal``, ``business``, ``consulting`` — a user on the
``personal`` profile should not be able to request or receive ``business``
data via natural language.

This differs from RLS (Layer 10): RLS catches explicit ``profile_id=xxx``
references in structured data.  DLP catches natural-language cross-profile
requests like "show me the business invoices" when operating under
``personal``.
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

# Context words that indicate data access intent
_CONTEXT_WORDS = re.compile(
    r"\b(?:data|invoices?|clients?|accounts?|reports?|records?|"
    r"files?|documents?|info(?:rmation)?|metrics?|analytics?|"
    r"details?|history|settings?|credentials?|contacts?)\b",
    re.IGNORECASE,
)


class DLPBlockLayer(SecurityLayer):
    """Layer 2 — block cross-profile data access in natural language."""

    name: str = "dlp_block"

    def __init__(self, profile_ids: list[str] | None = None) -> None:
        self._profile_ids = set(profile_ids or [])

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        foreign = self._detect_foreign_profile_refs(message, context.profile_id)
        if foreign:
            reason = f"cross-profile access: {', '.join(foreign)}"
            return SecurityResult(
                allowed=False,
                message=message,
                events=[{
                    "layer": self.name,
                    "severity": "critical",
                    "action": "blocked",
                    "profileId": context.profile_id,
                    "details": {"foreign_profiles": foreign},
                }],
                blocked_reason=reason,
            )
        return SecurityResult(allowed=True, message=message)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        foreign = self._detect_foreign_profile_refs(message, context.profile_id)
        if foreign:
            reason = f"cross-profile data leak: {', '.join(foreign)}"
            return SecurityResult(
                allowed=False,
                message=message,
                events=[{
                    "layer": self.name,
                    "severity": "critical",
                    "action": "blocked",
                    "profileId": context.profile_id,
                    "details": {"foreign_profiles": foreign},
                }],
                blocked_reason=reason,
            )
        return SecurityResult(allowed=True, message=message)

    def _detect_foreign_profile_refs(
        self, text: str, current_profile: str
    ) -> list[str]:
        """Return foreign profile names/IDs referenced in *text*."""
        if not self._profile_ids:
            return []

        found: list[str] = []
        text_lower = text.lower()

        for pid in self._profile_ids:
            if pid == current_profile:
                continue
            pid_lower = pid.lower()
            # Check for profile name followed by (or near) a data-context word
            pattern = re.compile(
                rf"\b{re.escape(pid_lower)}\b", re.IGNORECASE
            )
            if pattern.search(text) and _CONTEXT_WORDS.search(text_lower):
                found.append(pid)

        return sorted(found)
