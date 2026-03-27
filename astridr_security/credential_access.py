"""Credential access control — Layer 8 of the security pipeline.

Controls access to secrets and credentials with full audit trail.
Every credential retrieval is logged.  Outbound messages are scanned
to ensure credentials never leak through the pipeline.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

from astridr.security.dpapi_cache import DPAPICredentialCache

if TYPE_CHECKING:
    from astridr.engine.telemetry import ConvexHandler

logger = structlog.get_logger()


# ─── Credential request patterns ──────────────────────────────────────

_CREDENTIAL_REQUEST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bget\s+(?:secret|credential|password|api[_\s-]?key|token)\b", re.I),
    re.compile(r"\bretrieve\s+(?:secret|credential|password|api[_\s-]?key|token)\b", re.I),
    re.compile(r"\bfetch\s+(?:secret|credential|password|api[_\s-]?key|token)\b", re.I),
    re.compile(r"\baccess\s+(?:secret|credential|password|api[_\s-]?key|token)\b", re.I),
    re.compile(r"\bshow\s+(?:me\s+)?(?:the\s+)?(?:secret|credential|password|api[_\s-]?key|token)\b", re.I),
]

_CREDENTIAL_VALUE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:sk|pk)[-_](?:live|test|prod)?[-_]?[A-Za-z0-9]{20,}\b"), "api_key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "jwt"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "private_key"),
]


# ─── Audit entry ─────────────────────────────────────────────────────


@dataclass
class CredentialAuditEntry:
    """Record of a single credential access."""

    key: str
    accessor_profile_id: str
    accessor_channel_id: str
    timestamp: float = field(default_factory=time.time)
    granted: bool = True
    reason: str = ""


# ─── CredentialStore ─────────────────────────────────────────────────


class CredentialStore:
    """Secure credential retrieval with audit trail.

    Phase 2 reads from environment variables.  Future phases will
    integrate 1Password or Vault.
    """

    def __init__(
        self,
        allowed_keys: set[str] | None = None,
        env_prefix: str = "ASTRIDR_SECRET_",
    ) -> None:
        self._allowed_keys = allowed_keys
        self._env_prefix = env_prefix
        self._audit_log: list[CredentialAuditEntry] = []

    async def get_secret(self, key: str, context: SecurityContext) -> str | None:
        """Retrieve a secret by *key*.  Every access is audited.

        Returns ``None`` if the key is not found or not allowed.
        """
        # Check allowlist (if configured)
        if self._allowed_keys is not None and key not in self._allowed_keys:
            entry = CredentialAuditEntry(
                key=key,
                accessor_profile_id=context.profile_id,
                accessor_channel_id=context.channel_id,
                granted=False,
                reason="key not in allowlist",
            )
            self._audit_log.append(entry)
            logger.warning(
                "credential_store.denied",
                key=key,
                profile_id=context.profile_id,
                reason="key not in allowlist",
            )
            return None

        env_var = f"{self._env_prefix}{key.upper()}"
        value = os.environ.get(env_var)  # secretref-ok

        entry = CredentialAuditEntry(
            key=key,
            accessor_profile_id=context.profile_id,
            accessor_channel_id=context.channel_id,
            granted=value is not None,
            reason="" if value is not None else "env var not found",
        )
        self._audit_log.append(entry)

        logger.info(
            "credential_store.access",
            key=key,
            profile_id=context.profile_id,
            found=value is not None,
        )

        return value

    async def list_available(self) -> list[str]:
        """List available secret key names (not values).

        Scans environment for keys with the configured prefix.
        """
        prefix = self._env_prefix
        keys: list[str] = []
        for var in os.environ:  # secretref-ok
            if var.startswith(prefix):
                keys.append(var[len(prefix):].lower())
        return sorted(keys)

    @property
    def audit_log(self) -> list[CredentialAuditEntry]:
        """Return a copy of the audit log."""
        return list(self._audit_log)


# ─── SecurityLayer implementation ──────────────────────────────────────


class CredentialAccessLayer(SecurityLayer):
    """Layer 8 — controls access to secrets and credentials.

    * **Inbound**: flags messages that request credential access (audited).
    * **Outbound**: ensures no raw credential values leak in responses.
    """

    name: str = "credential_access"

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Check if message requests credential access.  Flag but allow (audited)."""
        events: list[dict] = []

        for pattern in _CREDENTIAL_REQUEST_PATTERNS:
            if pattern.search(message):
                events.append(
                    {
                        "layer": self.name,
                        "severity": "warning",
                        "action": "flagged",
                        "profileId": context.profile_id,
                        "details": {
                            "reason": "credential access requested",
                            "pattern": pattern.pattern,
                        },
                    }
                )
                logger.info(
                    "credential_access.inbound_request",
                    profile_id=context.profile_id,
                    channel_id=context.channel_id,
                )
                break  # One flag is enough

        return SecurityResult(allowed=True, message=message, events=events)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Ensure no credentials leak in outbound messages."""
        events: list[dict] = []

        for pattern, cred_type in _CREDENTIAL_VALUE_PATTERNS:
            if pattern.search(message):
                events.append(
                    {
                        "layer": self.name,
                        "severity": "critical",
                        "action": "blocked",
                        "profileId": context.profile_id,
                        "details": {
                            "reason": "credential leak detected",
                            "credential_type": cred_type,
                        },
                    }
                )
                logger.warning(
                    "credential_access.outbound_leak_blocked",
                    credential_type=cred_type,
                    profile_id=context.profile_id,
                )
                return SecurityResult(
                    allowed=False,
                    message=message,
                    events=events,
                    blocked_reason=f"credential leak detected: {cred_type}",
                )

        return SecurityResult(allowed=True, message=message, events=events)


# ─── Environment variable secret patterns ──────────────────────────────

_SECRET_PATTERNS = [
    r".*_KEY$",
    r".*_SECRET$",
    r".*_TOKEN$",
    r".*_PASSWORD$",
    r".*_API_KEY$",
    r".*_PRIVATE_KEY$",
    r".*_CREDENTIALS$",
    r".*_AUTH$",
]

_SECRET_RE = re.compile("|".join(_SECRET_PATTERNS), re.IGNORECASE)


# ─── SimpleCredentialStore ───────────────────────────────────────────


class SimpleCredentialStore:
    """Lightweight credential retrieval with three-tier resolution.

    Unlike :class:`CredentialStore` (which requires a SecurityContext),
    this store uses a simple requester string and caches values in memory.

    Resolution chain (first match wins):
    1. Environment variable → if ``op://`` ref, resolve via ``op`` CLI
    2. 1Password direct lookup (``op read``)
    3. In-memory cache
    4. DPAPI on-disk cache (stale entries trigger background refresh)
    5. ``None``
    """

    def __init__(
        self,
        telemetry: ConvexHandler | None = None,
        dpapi_cache: DPAPICredentialCache | None = None,
        op_vault_name: str = "Astridr",
        cache_ttl_seconds: float = 86400.0,
        op_cli_timeout_seconds: float = 5.0,
    ) -> None:
        self._cache: dict[str, str] = {}
        self._access_log: list[dict[str, Any]] = []
        self._telemetry = telemetry
        self._dpapi_cache = dpapi_cache
        self._op_vault_name = op_vault_name
        self._cache_ttl_seconds = cache_ttl_seconds
        self._op_cli_timeout_seconds = op_cli_timeout_seconds

    @staticmethod
    def _close_proc_transport(proc: Any) -> None:
        """Close subprocess transport to prevent ResourceWarning on Windows."""
        if proc is None:
            return
        transport = getattr(proc, "_transport", None)
        if transport is None:
            return
        # Only close real transports, not AsyncMock attributes.
        if isinstance(transport, asyncio.BaseTransport):
            try:
                transport.close()
            except Exception:
                pass

    async def get_secret(self, key: str, requester: str = "system") -> str | None:
        """Retrieve a secret by key using the three-tier resolution chain.

        Resolution order:
        1. Environment variable (``op://`` refs resolved via CLI)
        2. 1Password direct lookup via ``op read``
        3. In-memory cache
        4. DPAPI on-disk cache (stale entries still served, refresh scheduled)
        5. ``None``
        """
        # 1. Environment variable
        value = os.environ.get(key)  # secretref-ok
        if value is not None:
            if value.startswith("op://"):
                resolved = await self._resolve_op_reference(value)
                if resolved:
                    self._cache[key] = resolved
                    await self._dpapi_put(key, resolved, "op_ref")
                    self._log_access(key, requester, found=True, source="op_ref")
                    return resolved
                # op:// reference could not be resolved — fall through
            else:
                self._cache[key] = value
                await self._dpapi_put(key, value, "env")
                self._log_access(key, requester, found=True, source="env")
                return value

        # 2. 1Password direct lookup
        op_value = await self._resolve_op_direct(key)
        if op_value is not None:
            self._cache[key] = op_value
            await self._dpapi_put(key, op_value, "op_cli")
            self._log_access(key, requester, found=True, source="op_cli")
            return op_value

        # 3. In-memory cache
        if key in self._cache:
            self._log_access(key, requester, found=True, source="memory_cache")
            return self._cache[key]

        # 4. DPAPI on-disk cache
        dpapi_value, is_stale = await self._dpapi_get(key)
        if dpapi_value is not None:
            self._cache[key] = dpapi_value
            if is_stale:
                self._schedule_background_refresh(key, requester)
                self._log_access(key, requester, found=True, source="dpapi_stale")
            else:
                self._log_access(key, requester, found=True, source="dpapi_cache")
            return dpapi_value

        # 5. Not found
        self._log_access(key, requester, found=False, source="none")
        return None

    # ── 1Password resolution ────────────────────────────────────────────

    async def _resolve_op_reference(self, ref: str) -> str | None:
        """Resolve a 1Password ``op://`` reference via the CLI."""
        if not ref.startswith("op://"):
            return None

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "op", "read", ref,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._op_cli_timeout_seconds
            )
            if proc.returncode == 0:
                return stdout.decode().strip()
            logger.warning(
                "credential.op_failed",
                ref=ref,
                error=stderr.decode().strip(),
            )
            return None
        except asyncio.TimeoutError:
            if proc is not None:
                proc.kill()
                await proc.wait()
            logger.warning("credential.op_timeout", ref=ref)
            return None
        except FileNotFoundError:
            logger.debug("credential.op_not_installed")
            return None
        except Exception as exc:
            logger.warning("credential.op_error", ref=ref, error=str(exc))
            return None
        finally:
            self._close_proc_transport(proc)

    async def _resolve_op_direct(self, key: str) -> str | None:
        """Try direct 1Password lookup: ``op read "op://{vault}/{key}/credential"``."""
        ref = f"op://{self._op_vault_name}/{key}/credential"
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "op", "read", ref,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._op_cli_timeout_seconds
            )
            if proc.returncode == 0:
                return stdout.decode().strip()
            # Not found in 1Password — this is expected for many keys
            return None
        except (FileNotFoundError, asyncio.TimeoutError):
            if proc is not None:
                proc.kill()
                await proc.wait()
            return None
        except Exception:
            return None
        finally:
            self._close_proc_transport(proc)

    # ── DPAPI cache delegation ──────────────────────────────────────────

    async def _dpapi_get(self, key: str) -> tuple[str | None, bool]:
        """Retrieve from DPAPI cache, or ``(None, False)`` if unavailable."""
        if self._dpapi_cache is None:
            return None, False
        return await self._dpapi_cache.get(key)

    async def _dpapi_put(self, key: str, value: str, source: str) -> None:
        """Store in DPAPI cache if available."""
        if self._dpapi_cache is not None:
            await self._dpapi_cache.put(key, value, source)

    # ── Background refresh for stale entries ────────────────────────────

    def _schedule_background_refresh(self, key: str, requester: str) -> None:
        """Fire-and-forget background refresh for stale DPAPI entries."""
        try:
            asyncio.create_task(self._background_refresh(key, requester))
        except RuntimeError:
            # No running event loop — skip refresh
            pass

    async def _background_refresh(self, key: str, requester: str) -> None:
        """Re-attempt 1Password/env resolution and update caches."""
        try:
            # Try env first
            value = os.environ.get(key)  # secretref-ok
            if value is not None:
                if value.startswith("op://"):
                    value = await self._resolve_op_reference(value)
                if value:
                    self._cache[key] = value
                    await self._dpapi_put(key, value, "env")
                    return

            # Try 1Password direct
            op_value = await self._resolve_op_direct(key)
            if op_value is not None:
                self._cache[key] = op_value
                await self._dpapi_put(key, op_value, "op_cli")
        except Exception as exc:
            logger.debug("credential.background_refresh_failed", key=key, error=str(exc))

    # ── Public API (unchanged) ──────────────────────────────────────────

    async def list_available(self) -> list[str]:
        """Return sorted env var names that look like secrets."""
        return sorted(n for n in os.environ if self._is_secret_env_var(n))  # secretref-ok

    def get_access_log(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent access events, most recent first."""
        return list(reversed(self._access_log[-limit:]))

    def _log_access(
        self, key: str, requester: str, found: bool, source: str = ""
    ) -> None:
        self._access_log.append({
            "key": key,
            "requester": requester,
            "found": found,
            "timestamp": time.time(),
            "source": source,
        })
        logger.debug(
            "credential.access",
            key=key, requester=requester, found=found, source=source,
        )

    @staticmethod
    def _is_secret_env_var(name: str) -> bool:
        """Check if env var name matches a secret pattern."""
        return bool(_SECRET_RE.match(name))
