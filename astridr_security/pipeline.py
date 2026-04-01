"""Security pipeline — orchestrates the multi-layer security stack.

Every inbound and outbound message passes through this pipeline.
Layers are executed in order; any layer may modify or block the message.
Each layer emits ``security_event`` telemetry via :class:`ConvexHandler`.

16-layer security (12 pipeline + 4 complementary, optional DM pairing = 17):

Pipeline layers (12 active, 13 with DM pairing):
  1. PII Filter        2. DLP Block          3. Injection Defense
  4. Blocklist         5. Sensitive Action    [6. DM Pairing — optional]
  7. Secret Redactor   8. Credential Access   9. Egress Control
  10. RLS Enforcement  11. Output Filter      12. Audit Logger
  13. HITL Gate

Complementary security (outside the pipeline):
  14. Path Containment (``path_containment.py``) — used by PluginLoader/SkillCreator
  15. Approval Gates (``approval_gates.py``) — used by tool executor
  16. Budget Enforcement (``engine/budget.py``) — wraps LLM provider
  17. Emergency Stop (``engine/emergency_stop.py``) — router-level kill switch
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from astridr.engine.telemetry import ConvexHandler

from astridr.core.types import SecurityContext

logger = structlog.get_logger()


# ─── Shared data-classes ──────────────────────────────────────────────────


@dataclass
class SecurityResult:
    """Outcome of a single security-layer check.

    *allowed* — ``True`` if the message may proceed.
    *message* — the (possibly redacted) text.
    *events* — telemetry payloads to emit.
    *blocked_reason* — human-readable reason when blocked.
    """

    allowed: bool
    message: str
    events: list[dict] = field(default_factory=list)
    blocked_reason: str | None = None


# ─── Abstract layer interface ───────────────────────────────────────────


class SecurityLayer(ABC):
    """Base class for all security layers.

    Subclasses **must** set *name* and implement both process methods.
    """

    name: str

    @abstractmethod
    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Process an inbound (user -> agent) message."""
        ...

    @abstractmethod
    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Process an outbound (agent -> channel) message."""
        ...


# ─── Pipeline ───────────────────────────────────────────────────────


class SecurityPipeline:
    """Runs an ordered list of :class:`SecurityLayer` instances.

    If any layer blocks the message the pipeline short-circuits and
    returns immediately.
    """

    def __init__(
        self,
        layers: list[SecurityLayer],
        telemetry: ConvexHandler | None = None,
    ) -> None:
        self._layers = layers
        self._telemetry = telemetry

    @property
    def layers(self) -> list[SecurityLayer]:
        return list(self._layers)

    # ── public API ────────────────────────────────────────────────────

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Run all layers on an inbound message."""
        return await self._run(message, context, direction="inbound")

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Run all layers on an outbound message."""
        return await self._run(message, context, direction="outbound")

    # ── internal ──────────────────────────────────────────────────────

    async def _run(
        self,
        message: str,
        context: SecurityContext,
        *,
        direction: str,
    ) -> SecurityResult:
        all_events: list[dict] = []
        current_message = message

        for layer in self._layers:
            start = time.monotonic()

            if direction == "inbound":
                result = await layer.process_inbound(current_message, context)
            else:
                result = await layer.process_outbound(current_message, context)

            elapsed_ms = round((time.monotonic() - start) * 1000, 2)

            # Emit telemetry for every layer invocation
            for evt in result.events:
                evt.setdefault("profileId", context.profile_id)
                evt.setdefault("channelId", context.channel_id)
                evt.setdefault("direction", direction)
                evt.setdefault("elapsed_ms", elapsed_ms)
                await self._emit(evt)

            all_events.extend(result.events)

            if not result.allowed:
                logger.warning(
                    "security.blocked",
                    layer=layer.name,
                    direction=direction,
                    reason=result.blocked_reason,
                    profile_id=context.profile_id,
                )
                return SecurityResult(
                    allowed=False,
                    message=result.message,
                    events=all_events,
                    blocked_reason=f"[{layer.name}] {result.blocked_reason}",
                )

            current_message = result.message

        return SecurityResult(
            allowed=True,
            message=current_message,
            events=all_events,
        )

    def add_layer(self, layer: SecurityLayer) -> None:
        """Append a layer to the pipeline."""
        self._layers.append(layer)

    def add_layers(self, layers: list[SecurityLayer]) -> None:
        """Append multiple layers to the pipeline."""
        self._layers.extend(layers)

    async def _emit(self, event_data: dict) -> None:
        """Send a security_event through telemetry (if available)."""
        if self._telemetry is not None:
            await self._telemetry.send("security_event", event_data)


def build_full_pipeline(
    *,
    telemetry: ConvexHandler | None = None,
    audit_log_dir: Path | None = None,
    egress_allowed_domains: list[str] | None = None,
    egress_blocked_domains: list[str] | None = None,
    hitl_approval_callback: object | None = None,
    hitl_block_on_escalation: bool = False,
    dm_pairing_enabled: bool = False,
    dm_pairs_file: Path | None = None,
    persistence: object | None = None,
    profile_ids: list[str] | None = None,
    owner_mode: bool = False,
) -> SecurityPipeline:
    """Build the pipeline portion of the 16-layer security stack.

    Returns a :class:`SecurityPipeline` with 12 layers (13 with DM pairing).
    The remaining 4 layers are complementary (path containment, approval gates,
    budget enforcement, emergency stop) and enforced outside the pipeline.
    """
    from astridr.security.blocklist import BlocklistLayer
    from astridr.security.credential_access import CredentialAccessLayer
    from astridr.security.dlp_block import DLPBlockLayer
    from astridr.security.egress_control import EgressControlLayer
    from astridr.security.hitl_gate import HITLGateLayer
    from astridr.security.injection_defense import InjectionDefenseLayer
    from astridr.security.output_filter import OutputFilterLayer
    from astridr.security.pii_filter import PIIFilterLayer
    from astridr.security.rls_enforcement import RLSEnforcementLayer
    from astridr.security.secret_scanner import SecretRedactorLayer
    from astridr.security.sensitive_action import SensitiveActionLayer

    from astridr.security.audit_logger import AuditLoggerLayer

    layers: list[SecurityLayer] = [
        # Layer 1: PII Filter
        PIIFilterLayer(),
        # Layer 2: DLP Block
        DLPBlockLayer(profile_ids=profile_ids, owner_mode=owner_mode),
        # Layer 3: Injection Defense
        InjectionDefenseLayer(),
        # Layer 4: Blocklist
        BlocklistLayer(),
        # Layer 5: Sensitive Action
        SensitiveActionLayer(),
        # Layer 6: DM Pairing (optional — enabled via config)
    ]

    if dm_pairing_enabled:
        from astridr.security.dm_pairing import DMPairingLayer

        _pairs_path = dm_pairs_file or Path("config/dm_pairs.json")
        layers.append(DMPairingLayer(approved_pairs_file=_pairs_path, telemetry=telemetry))

    layers.extend([
        # Layer 7: Secret Redactor
        SecretRedactorLayer(),
        # Layer 8: Credential Access
        CredentialAccessLayer(),
        # Layer 9: Egress Control
        EgressControlLayer(
            allowed_domains=egress_allowed_domains,
            blocked_domains=egress_blocked_domains,
        ),
        # Layer 10: RLS Enforcement
        RLSEnforcementLayer(),
        # Layer 11: Output Filter
        OutputFilterLayer(),
        # Layer 12: Audit Logger
        AuditLoggerLayer(log_dir=audit_log_dir, persistence=persistence),
        # Layer 13: HITL Gate
        HITLGateLayer(
            approval_callback=hitl_approval_callback,  # type: ignore[arg-type]
            block_on_escalation=hitl_block_on_escalation,
        ),
    ])

    return SecurityPipeline(layers=layers, telemetry=telemetry)
