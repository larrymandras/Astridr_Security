"""DM pairing security layer — require approval before accepting DMs.

Unknown senders are held in a pending state until an admin explicitly
approves the (channel_id, sender_id) pair.  Approved pairs are persisted
to a JSON file via ``atomic_io``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from astridr.security.pipeline import SecurityContext, SecurityLayer, SecurityResult

if TYPE_CHECKING:
    from astridr.engine.telemetry import ConvexHandler

logger = structlog.get_logger()


class DMPairingLayer(SecurityLayer):
    """Block messages from unapproved DM senders.

    Approved pairs are loaded from *approved_pairs_file* at init and
    persisted on every mutation.

    Args:
        approved_pairs_file: JSON file storing approved pairs.
        telemetry: Optional telemetry handler.
    """

    name = "dm_pairing"

    def __init__(
        self,
        approved_pairs_file: Path,
        telemetry: ConvexHandler | None = None,
    ) -> None:
        self._file = Path(approved_pairs_file)
        self._telemetry = telemetry
        # channel_id -> set of sender_ids
        self._pairs: dict[str, set[str]] = {}
        # pending approval: (channel_id, sender_id)
        self._pending: set[tuple[str, str]] = set()
        self._load()

    # ── SecurityLayer interface ───────────────────────────────────────

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Check whether the sender is approved for this channel."""
        key = (context.channel_id, context.sender_id)

        if self._is_approved(key):
            return SecurityResult(allowed=True, message=message)

        if key in self._pending:
            return SecurityResult(
                allowed=False,
                message=message,
                blocked_reason="Awaiting DM approval",
            )

        # New unknown sender — add to pending
        self._pending.add(key)
        logger.info(
            "dm_pairing.new_pending",
            channel_id=context.channel_id,
            sender_id=context.sender_id,
        )

        if self._telemetry is not None:
            await self._telemetry.send(
                "security_event",
                {
                    "layer": "dm_pairing",
                    "action": "pending",
                    "channelId": context.channel_id,
                    "senderId": context.sender_id,
                },
            )

        return SecurityResult(
            allowed=False,
            message=message,
            blocked_reason="DM pairing required",
        )

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Outbound messages pass through unmodified."""
        return SecurityResult(allowed=True, message=message)

    # ── Approval management ──────────────────────────────────────

    def _is_approved(self, key: tuple[str, str]) -> bool:
        channel_id, sender_id = key
        return sender_id in self._pairs.get(channel_id, set())

    async def approve(self, channel_id: str, sender_id: str) -> None:
        """Approve a sender for a channel."""
        self._pairs.setdefault(channel_id, set()).add(sender_id)
        self._pending.discard((channel_id, sender_id))
        await self._save()
        logger.info("dm_pairing.approved", channel_id=channel_id, sender_id=sender_id)

    async def revoke(self, channel_id: str, sender_id: str) -> None:
        """Revoke approval for a sender."""
        senders = self._pairs.get(channel_id, set())
        senders.discard(sender_id)
        if not senders:
            self._pairs.pop(channel_id, None)
        await self._save()
        logger.info("dm_pairing.revoked", channel_id=channel_id, sender_id=sender_id)

    def list_pending(self) -> list[tuple[str, str]]:
        """Return all pending (channel_id, sender_id) pairs."""
        return list(self._pending)

    def list_approved(self) -> dict[str, list[str]]:
        """Return all approved pairs as {channel_id: [sender_ids]}."""
        return {ch: sorted(senders) for ch, senders in self._pairs.items()}

    # ── Persistence ──────────────────────────────────────────────

    def _load(self) -> None:
        """Load approved pairs from JSON file."""
        if not self._file.exists():
            return
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            for channel_id, senders in data.items():
                self._pairs[channel_id] = set(senders)
            logger.debug("dm_pairing.loaded", pairs=sum(len(s) for s in self._pairs.values()))
        except Exception as exc:
            logger.warning("dm_pairing.load_failed", error=str(exc))

    async def _save(self) -> None:
        """Persist approved pairs to JSON file."""
        from astridr.engine.atomic_io import atomic_json_write

        serializable = {ch: sorted(senders) for ch, senders in self._pairs.items()}
        await atomic_json_write(self._file, serializable)
