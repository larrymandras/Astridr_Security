"""DPAPI-encrypted credential cache — Windows-specific encrypted on-disk storage.

Uses Windows Data Protection API (DPAPI) to encrypt secrets at rest,
bound to the current Windows user account.  Falls back to no-op on
non-Windows platforms.

Storage backend is SQLite via aiosqlite for async access.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

try:
    import win32crypt  # type: ignore[import-untyped]

    _DPAPI_AVAILABLE = True
except ImportError:
    _DPAPI_AVAILABLE = False

try:
    import aiosqlite  # type: ignore[import-untyped]

    _AIOSQLITE_AVAILABLE = True
except ImportError:
    _AIOSQLITE_AVAILABLE = False

if TYPE_CHECKING:
    from astridr.engine.telemetry import ConvexHandler

logger = structlog.get_logger()

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS credentials (
    key          TEXT PRIMARY KEY,
    encrypted_value  BLOB NOT NULL,
    fetched_at   REAL NOT NULL,
    source       TEXT NOT NULL DEFAULT 'unknown'
)
"""


class DPAPICredentialCache:
    """DPAPI-encrypted SQLite credential cache.

    All methods are async and no-op gracefully when DPAPI or aiosqlite
    is unavailable (e.g. on Linux/macOS or missing dependency).
    """

    def __init__(
        self,
        db_path: str | Path = "~/.astridr/cache/credentials.db",
        ttl_seconds: float = 86400.0,
        telemetry: ConvexHandler | None = None,
    ) -> None:
        self._db_path = Path(db_path).expanduser()
        self._ttl_seconds = ttl_seconds
        self._telemetry = telemetry
        self._db: Any = None  # aiosqlite.Connection

    @property
    def available(self) -> bool:
        """Whether DPAPI encryption and aiosqlite are both available."""
        return _DPAPI_AVAILABLE and _AIOSQLITE_AVAILABLE

    async def init(self) -> None:
        """Create the database directory, file, and table."""
        if not self.available:
            logger.debug(
                "dpapi_cache.unavailable",
                dpapi=_DPAPI_AVAILABLE,
                aiosqlite=_AIOSQLITE_AVAILABLE,
            )
            return

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.execute(_CREATE_TABLE_SQL)
        await self._db.commit()
        logger.info("dpapi_cache.initialized", db_path=str(self._db_path))

    async def get(self, key: str) -> tuple[str | None, bool]:
        """Retrieve a cached credential.

        Returns ``(value, is_stale)`` or ``(None, False)`` on miss.
        """
        if self._db is None:
            await self._emit("dpapi_cache.miss", key=key)
            return None, False

        cursor = await self._db.execute(
            "SELECT encrypted_value, fetched_at FROM credentials WHERE key = ?",
            (key,),
        )
        row = await cursor.fetchone()
        if row is None:
            await self._emit("dpapi_cache.miss", key=key)
            return None, False

        encrypted_value, fetched_at = row
        try:
            value = self._decrypt(encrypted_value)
        except Exception:
            logger.warning("dpapi_cache.decrypt_error", key=key)
            await self._emit("dpapi_cache.decrypt_error", key=key)
            return None, False

        is_stale = (time.time() - fetched_at) > self._ttl_seconds
        if is_stale:
            await self._emit("dpapi_cache.hit_stale", key=key)
        else:
            await self._emit("dpapi_cache.hit", key=key)

        return value, is_stale

    async def put(self, key: str, value: str, source: str = "unknown") -> None:
        """Encrypt and upsert a credential."""
        if self._db is None:
            return

        try:
            encrypted = self._encrypt(value)
        except Exception:
            logger.warning("dpapi_cache.encrypt_error", key=key)
            await self._emit("dpapi_cache.encrypt_error", key=key)
            return

        await self._db.execute(
            """
            INSERT INTO credentials (key, encrypted_value, fetched_at, source)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                encrypted_value = excluded.encrypted_value,
                fetched_at = excluded.fetched_at,
                source = excluded.source
            """,
            (key, encrypted, time.time(), source),
        )
        await self._db.commit()

    async def delete(self, key: str) -> None:
        """Remove a single credential from the cache."""
        if self._db is None:
            return
        await self._db.execute("DELETE FROM credentials WHERE key = ?", (key,))
        await self._db.commit()

    async def clear(self) -> None:
        """Remove all credentials from the cache."""
        if self._db is None:
            return
        await self._db.execute("DELETE FROM credentials")
        await self._db.commit()

    async def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        if self._db is None:
            return {"total": 0, "stale_count": 0, "oldest": None}

        now = time.time()
        stale_cutoff = now - self._ttl_seconds

        cursor = await self._db.execute("SELECT COUNT(*) FROM credentials")
        total = (await cursor.fetchone())[0]

        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM credentials WHERE fetched_at < ?",
            (stale_cutoff,),
        )
        stale_count = (await cursor.fetchone())[0]

        cursor = await self._db.execute(
            "SELECT MIN(fetched_at) FROM credentials"
        )
        oldest_row = await cursor.fetchone()
        oldest = oldest_row[0] if oldest_row and oldest_row[0] is not None else None

        return {"total": total, "stale_count": stale_count, "oldest": oldest}

    async def close(self) -> None:
        """Close the database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None

    # ── Encryption helpers ────────────────────────────────────────────

    @staticmethod
    def _encrypt(value: str) -> bytes:
        """Encrypt a string using DPAPI."""
        data = value.encode("utf-8")
        result = win32crypt.CryptProtectData(
            data, "astridr-credential", None, None, None, 0
        )
        # pywin32 returns bytes directly or (desc, bytes) depending on version
        return result[-1] if isinstance(result, tuple) else result

    @staticmethod
    def _decrypt(encrypted: bytes) -> str:
        """Decrypt bytes using DPAPI."""
        result = win32crypt.CryptUnprotectData(
            encrypted, None, None, None, 0
        )
        raw = result[-1] if isinstance(result, tuple) else result
        return raw.decode("utf-8")

    # ── Telemetry helper ──────────────────────────────────────────────

    async def _emit(self, event: str, **kwargs: Any) -> None:
        if self._telemetry is not None:
            try:
                await self._telemetry.send(event, kwargs)
            except Exception as exc:
                logger.debug("dpapi_cache.telemetry_error", error=str(exc))
