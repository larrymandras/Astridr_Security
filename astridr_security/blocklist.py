"""Command blocklist — blocks dangerous shell commands and path accesses.

Layer 4 of the security pipeline.
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


# ─── Result dataclass ─────────────────────────────────────────────


@dataclass
class BlocklistResult:
    """Result of a blocklist check."""

    blocked: bool
    reason: str | None = None
    matched_pattern: str | None = None


# ─── Default blocked patterns ─────────────────────────────────────

_BLOCKED_COMMANDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\brm\s+-\w*r\w*f\w*\s+/", re.I), "recursive delete from root"),
    (re.compile(r"\bmkfs\b", re.I), "filesystem format"),
    (re.compile(r"\bdd\s+if=", re.I), "raw disk write"),
    (re.compile(r":\(\)\s*\{\s*:\|\s*:\s*&\s*\}\s*;?\s*:", re.I), "fork bomb"),
    (re.compile(r"\bchmod\s+777\b", re.I), "world-writable permissions"),
    (re.compile(r"\bgit\s+push\s+--force\b", re.I), "force push"),
    (re.compile(r"\bcurl\b.*\|\s*(?:ba)?sh\b", re.I), "pipe to shell"),
    (re.compile(r"\bwget\b.*\|\s*(?:ba)?sh\b", re.I), "pipe to shell"),
    (re.compile(r"\bshutdown\b", re.I), "system shutdown"),
    (re.compile(r"\breboot\b", re.I), "system reboot"),
    (re.compile(r"\bsudo\s+rm\b", re.I), "privileged delete"),
    (re.compile(r"\b(?:halt|poweroff|init\s+0)\b", re.I), "system halt"),
]

_BLOCKED_PATHS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.env\b"), ".env file access"),
    (re.compile(r"\.ssh[/\\]"), ".ssh directory access"),
    (re.compile(r"\.gnupg[/\\]"), ".gnupg directory access"),
    (re.compile(r"/etc/(?:passwd|shadow|sudoers)"), "system credential file"),
    (re.compile(r"/proc/"), "/proc access"),
    (re.compile(r"/sys/"), "/sys access"),
    (re.compile(r"C:\\Windows\\System32", re.I), "Windows system directory"),
]


# ─── Public API ───────────────────────────────────────────────────


def check_command(
    text: str,
    *,
    extra_patterns: list[tuple[re.Pattern[str], str]] | None = None,
) -> BlocklistResult:
    """Check *text* against the command blocklist.

    *extra_patterns* allows per-profile additions.
    """
    patterns = list(_BLOCKED_COMMANDS)
    if extra_patterns:
        patterns.extend(extra_patterns)

    for pattern, reason in patterns:
        if pattern.search(text):
            return BlocklistResult(blocked=True, reason=reason, matched_pattern=pattern.pattern)

    return BlocklistResult(blocked=False)


def check_path(
    text: str,
    *,
    extra_patterns: list[tuple[re.Pattern[str], str]] | None = None,
) -> BlocklistResult:
    """Check *text* for references to blocked paths."""
    patterns = list(_BLOCKED_PATHS)
    if extra_patterns:
        patterns.extend(extra_patterns)

    for pattern, reason in patterns:
        if pattern.search(text):
            return BlocklistResult(blocked=True, reason=reason, matched_pattern=pattern.pattern)

    return BlocklistResult(blocked=False)


def check(
    text: str,
    *,
    extra_command_patterns: list[tuple[re.Pattern[str], str]] | None = None,
    extra_path_patterns: list[tuple[re.Pattern[str], str]] | None = None,
) -> BlocklistResult:
    """Combined command + path blocklist check."""
    cmd_result = check_command(text, extra_patterns=extra_command_patterns)
    if cmd_result.blocked:
        return cmd_result
    return check_path(text, extra_patterns=extra_path_patterns)


# ─── SecurityLayer implementation ─────────────────────────────────


class BlocklistLayer(SecurityLayer):
    """Layer 4 — block dangerous commands and path accesses."""

    name: str = "blocklist"

    def __init__(
        self,
        extra_command_patterns: list[tuple[re.Pattern[str], str]] | None = None,
        extra_path_patterns: list[tuple[re.Pattern[str], str]] | None = None,
    ) -> None:
        self._extra_commands = extra_command_patterns
        self._extra_paths = extra_path_patterns

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        result = check(
            message,
            extra_command_patterns=self._extra_commands,
            extra_path_patterns=self._extra_paths,
        )
        events: list[dict] = []

        if result.blocked:
            events.append(
                {
                    "layer": self.name,
                    "severity": "critical",
                    "action": "blocked",
                    "profileId": context.profile_id,
                    "details": {
                        "reason": result.reason,
                        "pattern": result.matched_pattern,
                    },
                }
            )
            return SecurityResult(
                allowed=False,
                message=message,
                events=events,
                blocked_reason=result.reason,
            )

        return SecurityResult(allowed=True, message=message, events=events)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        # Outbound: also check for dangerous commands the model might emit
        result = check(
            message,
            extra_command_patterns=self._extra_commands,
            extra_path_patterns=self._extra_paths,
        )
        events: list[dict] = []

        if result.blocked:
            events.append(
                {
                    "layer": self.name,
                    "severity": "warning",
                    "action": "flagged",
                    "profileId": context.profile_id,
                    "details": {
                        "reason": result.reason,
                        "pattern": result.matched_pattern,
                    },
                }
            )
            logger.warning(
                "blocklist.outbound_flagged",
                reason=result.reason,
                profile_id=context.profile_id,
            )

        # Outbound dangerous commands are flagged, not blocked
        return SecurityResult(allowed=True, message=message, events=events)
