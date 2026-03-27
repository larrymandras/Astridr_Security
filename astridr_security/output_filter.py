"""Output filter — Layer 11 of the security pipeline.

Filters sensitive content from LLM output before delivery to the
user.  Catches credential assignments and config-style secrets that
might slip through the earlier secret scanner layer.
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


# ─── Filter patterns ─────────────────────────────────────────────────

# Each tuple: (compiled regex, replacement text)
FILTER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.I),
        "[FILTERED:password]",
    ),
    (
        re.compile(r"(?:api[_\-]?key|apikey)\s*[:=]\s*\S+", re.I),
        "[FILTERED:api_key]",
    ),
    (
        re.compile(r"(?:secret|token)\s*[:=]\s*\S+", re.I),
        "[FILTERED:secret]",
    ),
    (
        re.compile(r"(?:connection[_\-]?string)\s*[:=]\s*\S+", re.I),
        "[FILTERED:connection_string]",
    ),
    (
        re.compile(r"(?:database[_\-]?url|db[_\-]?url)\s*[:=]\s*\S+", re.I),
        "[FILTERED:database_url]",
    ),
]


# ─── Public API ──────────────────────────────────────────────────────


def filter_output(text: str, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> tuple[str, int]:
    """Apply filter patterns to *text*.

    Returns a tuple of (filtered_text, number_of_replacements).
    """
    active_patterns = patterns if patterns is not None else FILTER_PATTERNS
    total_replacements = 0
    result = text

    for pattern, replacement in active_patterns:
        result, count = pattern.subn(replacement, result)
        total_replacements += count

    return result, total_replacements


# ─── SecurityLayer implementation ──────────────────────────────────────


class OutputFilterLayer(SecurityLayer):
    """Layer 11 — filters sensitive content from LLM output.

    * **Inbound**: passes through (output filter only applies to outbound).
    * **Outbound**: applies filter patterns, replacing matches with
      ``[FILTERED:type]`` placeholders.
    """

    name: str = "output_filter"

    def __init__(
        self,
        extra_patterns: list[tuple[re.Pattern[str], str]] | None = None,
    ) -> None:
        self._patterns = list(FILTER_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Inbound: pass through (output filter only checks outbound)."""
        return SecurityResult(allowed=True, message=message)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Apply filter patterns to outbound message."""
        filtered, count = filter_output(message, self._patterns)
        events: list[dict] = []

        if count > 0:
            events.append(
                {
                    "layer": self.name,
                    "severity": "warning",
                    "action": "filtered",
                    "profileId": context.profile_id,
                    "details": {
                        "replacements": count,
                    },
                }
            )
            logger.info(
                "output_filter.filtered",
                replacements=count,
                profile_id=context.profile_id,
            )

        return SecurityResult(allowed=True, message=filtered, events=events)
