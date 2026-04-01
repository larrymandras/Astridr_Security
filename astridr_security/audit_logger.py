"""Audit logger — audit logging layer of the security pipeline.

Provides tamper-evident, append-only audit logging with a hash chain.
Every inbound and outbound message is logged with metadata.  The hash
chain allows integrity verification of the log.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import structlog

from astridr.engine.atomic_io import atomic_write
from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

logger = structlog.get_logger()


# ─── Constants ───────────────────────────────────────────────────────

_DEFAULT_LOG_DIR = Path("~/.astridr/audit").expanduser()
_GENESIS_HASH = "0" * 64  # SHA-256 of nothing — chain anchor


# ─── Audit logger ────────────────────────────────────────────────────


class AuditLogger:
    """Append-only audit log with hash chain for tamper detection.

    Each entry contains:
    * ``timestamp`` — Unix epoch
    * ``event`` — the event payload
    * ``prev_hash`` — SHA-256 of the previous entry
    * ``hash`` — SHA-256 of this entry (without the hash field itself)
    """

    def __init__(
        self,
        log_dir: Path | None = None,
        persistence: Any | None = None,
    ) -> None:
        self._log_dir = log_dir or _DEFAULT_LOG_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / "audit.jsonl"
        self._prev_hash = _GENESIS_HASH
        self._persistence = persistence

        # Recover chain state from existing log
        self._recover_chain_state()

    def _recover_chain_state(self) -> None:
        """Read the last entry to recover prev_hash for chain continuity."""
        if not self._log_file.exists():
            return
        try:
            last_line = ""
            with open(self._log_file, encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if last_line:
                entry = json.loads(last_line)
                self._prev_hash = entry.get("hash", _GENESIS_HASH)
        except (json.JSONDecodeError, OSError):
            logger.warning("audit_logger.chain_recovery_failed")

    def _compute_hash(self, entry_data: dict) -> str:
        """Compute SHA-256 hash of an entry (excluding the 'hash' field)."""
        serialised = json.dumps(entry_data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(serialised.encode("utf-8")).hexdigest()

    async def log_event(self, event: dict) -> None:
        """Append an event to the audit log with hash chain."""
        entry_data = {
            "timestamp": time.time(),
            "event": event,
            "prev_hash": self._prev_hash,
        }
        entry_hash = self._compute_hash(entry_data)
        entry_data["hash"] = entry_hash

        line = json.dumps(entry_data, ensure_ascii=False) + "\n"

        # Append to log file
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._log_file, "a", encoding="utf-8") as f:
            f.write(line)

        self._prev_hash = entry_hash

        # Fire-and-forget persist to Supabase (never blocks pipeline)
        if self._persistence is not None:
            db_entry = {
                "timestamp": entry_data.get("timestamp"),
                "profile_id": event.get("profile_id", "unknown"),
                "channel_id": event.get("channel_id"),
                "direction": event.get("direction"),
                "event": event,
                "prev_hash": entry_data.get("prev_hash"),
                "hash": entry_hash,
            }
            self._persistence.insert_audit_log_bg(db_entry)

    async def verify_chain(self) -> bool:
        """Verify the integrity of the entire audit log hash chain.

        Returns ``True`` if the chain is valid, ``False`` if tampered.
        """
        if not self._log_file.exists():
            return True

        prev_hash = _GENESIS_HASH
        try:
            with open(self._log_file, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    entry = json.loads(stripped)

                    # Verify prev_hash chain
                    if entry.get("prev_hash") != prev_hash:
                        logger.warning(
                            "audit_logger.chain_broken",
                            line=line_num,
                            expected_prev=prev_hash,
                            actual_prev=entry.get("prev_hash"),
                        )
                        return False

                    # Verify self-hash
                    stored_hash = entry.pop("hash")
                    computed_hash = self._compute_hash(entry)
                    entry["hash"] = stored_hash

                    if stored_hash != computed_hash:
                        logger.warning(
                            "audit_logger.hash_mismatch",
                            line=line_num,
                        )
                        return False

                    prev_hash = stored_hash
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("audit_logger.verify_error", error=str(exc))
            return False

        return True

    @property
    def log_file(self) -> Path:
        """Return the path to the audit log file."""
        return self._log_file


# ─── SecurityLayer implementation ────────────────────────────────────


class AuditLoggerLayer(SecurityLayer):
    """Layer 12 — tamper-evident audit logging.

    Logs every inbound and outbound message.  Always passes through —
    this layer never blocks messages.
    """

    name: str = "audit_logger"

    def __init__(
        self,
        log_dir: Path | None = None,
        persistence: Any | None = None,
    ) -> None:
        self._logger = AuditLogger(log_dir=log_dir, persistence=persistence)

    @property
    def audit_logger(self) -> AuditLogger:
        """Expose the underlying AuditLogger for verification."""
        return self._logger

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Log inbound message (who, what, when, channel). Always passes."""
        await self._logger.log_event(
            {
                "direction": "inbound",
                "profile_id": context.profile_id,
                "channel_id": context.channel_id,
                "sender_id": context.sender_id,
                "session_id": context.session_id,
                "message_length": len(message),
            }
        )
        return SecurityResult(allowed=True, message=message)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Log outbound message. Always passes."""
        await self._logger.log_event(
            {
                "direction": "outbound",
                "profile_id": context.profile_id,
                "channel_id": context.channel_id,
                "message_length": len(message),
            }
        )
        return SecurityResult(allowed=True, message=message)
