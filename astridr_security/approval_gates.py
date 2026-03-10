"""Approval gates — tier-based tool authorization.

Three tiers control whether a tool invocation proceeds automatically
or requires explicit user approval:

* **read_only** — auto-approved (file reads, searches, status checks)
* **supervised** — requires user confirmation (writes, shell, sends)
* **autonomous** — auto-approved (trusted cron/automation only)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import structlog

logger = structlog.get_logger()


# ─── Tiers ────────────────────────────────────────────────────────


class ApprovalTier(str, Enum):
    READ_ONLY = "read_only"
    SUPERVISED = "supervised"
    AUTONOMOUS = "autonomous"


# ─── Result ───────────────────────────────────────────────────────


@dataclass
class ApprovalResult:
    approved: bool
    reason: str
    tier: ApprovalTier
    requires_user_input: bool = False


# ─── Default tool tier mapping ────────────────────────────────────

# Tools not listed here default to SUPERVISED.
_DEFAULT_TOOL_TIERS: dict[str, ApprovalTier] = {
    # Read-only tools
    "file_read": ApprovalTier.READ_ONLY,
    "file_search": ApprovalTier.READ_ONLY,
    "web_search": ApprovalTier.READ_ONLY,
    "status_check": ApprovalTier.READ_ONLY,
    "list_files": ApprovalTier.READ_ONLY,
    "memory_search": ApprovalTier.READ_ONLY,
    "get_time": ApprovalTier.READ_ONLY,
    "calendar_read": ApprovalTier.READ_ONLY,
    # Supervised tools
    "file_write": ApprovalTier.SUPERVISED,
    "file_delete": ApprovalTier.SUPERVISED,
    "shell_exec": ApprovalTier.SUPERVISED,
    "send_message": ApprovalTier.SUPERVISED,
    "send_email": ApprovalTier.SUPERVISED,
    "api_call": ApprovalTier.SUPERVISED,
    "git_commit": ApprovalTier.SUPERVISED,
    "git_push": ApprovalTier.SUPERVISED,
    "deploy": ApprovalTier.SUPERVISED,
    "calendar_write": ApprovalTier.SUPERVISED,
}


# ─── Gate logic ───────────────────────────────────────────────────


class ApprovalGate:
    """Determines whether a tool invocation should proceed.

    *profile_tier* overrides the default: if a profile is set to
    ``autonomous`` then all tools are auto-approved (for trusted
    cron jobs). If set to ``read_only`` then only read-only tools
    are approved.
    """

    def __init__(
        self,
        tool_tiers: dict[str, ApprovalTier] | None = None,
    ) -> None:
        self._tool_tiers: dict[str, ApprovalTier] = dict(_DEFAULT_TOOL_TIERS)
        if tool_tiers:
            self._tool_tiers.update(tool_tiers)

    def get_tier(self, tool_name: str) -> ApprovalTier:
        """Look up the tier for a tool. Unknown tools default to SUPERVISED."""
        return self._tool_tiers.get(tool_name, ApprovalTier.SUPERVISED)

    def check(
        self,
        tool_name: str,
        args: dict | None = None,
        *,
        profile_tier: ApprovalTier | None = None,
    ) -> ApprovalResult:
        """Check whether *tool_name* should be approved.

        Parameters
        ----------
        tool_name:
            Name of the tool being invoked.
        args:
            Tool arguments (for future rule-based checks).
        profile_tier:
            If the profile is ``autonomous``, all tools are approved.
            If ``read_only``, only read_only tools are approved.
        """
        tool_tier = self.get_tier(tool_name)

        # Autonomous profile — everything is auto-approved
        if profile_tier == ApprovalTier.AUTONOMOUS:
            return ApprovalResult(
                approved=True,
                reason="profile is autonomous",
                tier=tool_tier,
            )

        # Read-only profile — only read_only tools
        if profile_tier == ApprovalTier.READ_ONLY:
            if tool_tier == ApprovalTier.READ_ONLY:
                return ApprovalResult(
                    approved=True,
                    reason="read-only tool in read-only profile",
                    tier=tool_tier,
                )
            return ApprovalResult(
                approved=False,
                reason=f"tool '{tool_name}' requires '{tool_tier.value}' but profile is read-only",
                tier=tool_tier,
                requires_user_input=True,
            )

        # Default (supervised profile) or no profile_tier specified
        if tool_tier == ApprovalTier.READ_ONLY:
            return ApprovalResult(
                approved=True,
                reason="read-only tool auto-approved",
                tier=tool_tier,
            )

        if tool_tier == ApprovalTier.SUPERVISED:
            return ApprovalResult(
                approved=False,
                reason=f"tool '{tool_name}' requires user approval",
                tier=tool_tier,
                requires_user_input=True,
            )

        # AUTONOMOUS tier tool but profile is not autonomous
        return ApprovalResult(
            approved=False,
            reason=f"tool '{tool_name}' is autonomous-only, profile is not autonomous",
            tier=tool_tier,
            requires_user_input=True,
        )
