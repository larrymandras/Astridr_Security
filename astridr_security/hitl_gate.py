"""HITL gate — Layer 13 of the security pipeline.

Human-In-The-Loop escalation for critical actions.  Detects messages
that imply destructive or sensitive operations and flags them for
human approval.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

# Type alias for approval callbacks
ApprovalCallback = Callable[[str, dict, SecurityContext], Awaitable[bool]]

logger = structlog.get_logger()


# ─── Escalation triggers ──────────────────────────────────────────────

# Maps action names to detection patterns
ESCALATION_TRIGGERS: dict[str, list[re.Pattern[str]]] = {
    "file_delete": [
        re.compile(r"\bdelete\s+(?:file|folder|directory)\b", re.I),
        re.compile(r"\brm\s+-", re.I),
        re.compile(r"\bremove\s+(?:file|folder|directory)\b", re.I),
    ],
    "shell_exec_destructive": [
        re.compile(r"\bdrop\s+(?:table|database|schema)\b", re.I),
        re.compile(r"\btruncate\s+table\b", re.I),
        re.compile(r"\bformat\s+(?:disk|drive)\b", re.I),
    ],
    "email_send": [
        re.compile(r"\bsend\s+(?:an?\s+)?email\b", re.I),
        re.compile(r"\bemail\s+(?:to|send)\b", re.I),
    ],
    "git_push": [
        re.compile(r"\bgit\s+push\b", re.I),
        re.compile(r"\bpush\s+to\s+(?:main|master|prod)", re.I),
    ],
    "database_write": [
        re.compile(r"\bINSERT\s+INTO\b", re.I),
        re.compile(r"\bUPDATE\s+\w+\s+SET\b", re.I),
        re.compile(r"\bDELETE\s+FROM\b", re.I),
    ],
    "credential_access": [
        re.compile(r"\brotate\s+(?:key|secret|credential|token)\b", re.I),
        re.compile(r"\bchange\s+password\b", re.I),
    ],
}

# Default approval timeout (seconds)
DEFAULT_APPROVAL_TIMEOUT = 300  # 5 minutes


# ─── Approval result ─────────────────────────────────────────────────


@dataclass
class ApprovalRequest:
    """A pending HITL approval request."""

    action: str
    details: dict
    profile_id: str
    channel_id: str
    timestamp: float = field(default_factory=time.time)
    approved: bool | None = None  # None = pending
    response_timestamp: float | None = None


# ─── HITL Gate Layer ─────────────────────────────────────────────────


class HITLGateLayer(SecurityLayer):
    """Layer 13 — Human-In-The-Loop escalation for critical actions.

    Detects messages that imply critical actions and flags them.
    Approval is requested via the configured approval callback.

    * **Inbound**: detects critical action patterns and optionally
      blocks pending human approval.
    * **Outbound**: passes through.
    """

    name: str = "hitl_gate"

    def __init__(
        self,
        approval_callback: ApprovalCallback | None = None,
        timeout_seconds: int = DEFAULT_APPROVAL_TIMEOUT,
        block_on_escalation: bool = False,
    ) -> None:
        self._approval_callback = approval_callback
        self._timeout_seconds = timeout_seconds
        self._block_on_escalation = block_on_escalation
        self._pending_requests: list[ApprovalRequest] = []

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Detect if message implies a critical action."""
        is_critical, action = self._is_critical_action(message)
        events: list[dict] = []

        if is_critical and action:
            events.append(
                {
                    "layer": self.name,
                    "severity": "warning",
                    "action": "escalated",
                    "profileId": context.profile_id,
                    "details": {
                        "critical_action": action,
                        "requires_approval": self._block_on_escalation,
                    },
                }
            )
            logger.warning(
                "hitl_gate.escalation",
                critical_action=action,
                profile_id=context.profile_id,
            )

            if self._block_on_escalation:
                approved = await self.request_approval(
                    action,
                    {"message": message},
                    context,
                )
                if not approved:
                    return SecurityResult(
                        allowed=False,
                        message=message,
                        events=events,
                        blocked_reason=f"HITL approval denied or timed out for: {action}",
                    )

        return SecurityResult(allowed=True, message=message, events=events)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Outbound: pass through."""
        return SecurityResult(allowed=True, message=message)

    async def request_approval(
        self,
        action: str,
        details: dict,
        context: SecurityContext,
    ) -> bool:
        """Request approval via configured channel.

        Returns ``True`` if approved, ``False`` if denied or timed out.
        Timeout after ``timeout_seconds`` defaults to deny.
        """
        request = ApprovalRequest(
            action=action,
            details=details,
            profile_id=context.profile_id,
            channel_id=context.channel_id,
        )
        self._pending_requests.append(request)

        if self._approval_callback is None:
            logger.warning(
                "hitl_gate.no_callback",
                action=action,
                profile_id=context.profile_id,
            )
            request.approved = False
            request.response_timestamp = time.time()
            return False

        try:
            approved = await asyncio.wait_for(
                self._approval_callback(action, details, context),
                timeout=self._timeout_seconds,
            )
            request.approved = approved
            request.response_timestamp = time.time()
            return approved
        except asyncio.TimeoutError:
            logger.warning(
                "hitl_gate.timeout",
                action=action,
                profile_id=context.profile_id,
                timeout_seconds=self._timeout_seconds,
            )
            request.approved = False
            request.response_timestamp = time.time()
            return False

    def _is_critical_action(self, message: str) -> tuple[bool, str | None]:
        """Detect critical action patterns in message.

        Returns (is_critical, action_name).
        """
        for action, patterns in ESCALATION_TRIGGERS.items():
            for pattern in patterns:
                if pattern.search(message):
                    return True, action
        return False, None

    @property
    def pending_requests(self) -> list[ApprovalRequest]:
        """Return a copy of the pending requests list."""
        return list(self._pending_requests)
