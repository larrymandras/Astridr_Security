# Astridr Security

The security subsystem of the Astridr AI agent framework. Implements a **16+ layer security pipeline** that processes every inbound (user-to-agent) and outbound (agent-to-channel) message. Any layer can modify, flag, or block a message. The pipeline short-circuits on the first block.

## Architecture

The security stack is split into two categories:

- **Pipeline layers (12 active, 13 with DM pairing)** -- executed sequentially by `SecurityPipeline` on every message.
- **Complementary layers (4)** -- enforced outside the pipeline at specific integration points (plugin loader, tool executor, LLM provider, router).

## Pipeline Layers

| # | Layer | File | Purpose |
|---|-------|------|---------|
| 1 | PII Filter | `pii_filter.py` | Detect and redact personally identifiable information |
| 2 | DLP Block | `dlp_block.py` | Data Loss Prevention -- block exfiltration of sensitive data |
| 3 | Injection Defense | `injection_defense.py` | Detect and neutralize prompt injection attacks |
| 4 | Blocklist | `blocklist.py` | Block literal dangerous paths (`.env`, `.ssh/`) and commands (`rm -rf`) |
| 5 | Sensitive Action | `sensitive_action.py` | Flag semantic intent patterns for credential/privilege access |
| 6 | DM Pairing (optional) | `dm_pairing.py` | Require approval before accepting DMs from unknown senders |
| 7 | Secret Redactor | `secret_scanner.py` | Scan and redact secrets (API keys, tokens) from messages |
| 8 | Credential Access | `credential_access.py` | Control and audit access to stored credentials |
| 9 | Egress Control | `egress_control.py` | Allowlist/blocklist outbound domain access |
| 10 | RLS Enforcement | `rls_enforcement.py` | Row-Level Security -- enforce profile data isolation |
| 11 | Output Filter | `output_filter.py` | Final output sanitization before delivery |
| 12 | Audit Logger | `audit_logger.py` | Tamper-evident append-only audit log with hash chain |
| 13 | HITL Gate | `hitl_gate.py` | Human-In-The-Loop escalation for destructive/critical actions |

## Complementary Layers

| # | Layer | File | Enforcement Point |
|---|-------|------|--------------------|
| 14 | Path Containment | `path_containment.py` | PluginLoader / SkillCreator |
| 15 | Approval Gates | `approval_gates.py` | Tool executor |
| 16 | Budget Enforcement | `engine/budget.py` | LLM provider wrapper |
| 17 | Emergency Stop | `engine/emergency_stop.py` | Router-level kill switch |

## Supplementary Modules

| Module | File | Purpose |
|--------|------|---------|
| DPAPI Cache | `dpapi_cache.py` | Windows DPAPI-encrypted credential cache (SQLite + aiosqlite) |
| Pipeline Core | `pipeline.py` | `SecurityContext`, `SecurityLayer` ABC, `SecurityPipeline`, `build_full_pipeline()` |

## How `build_full_pipeline()` Assembles the Stack

`build_full_pipeline()` in `pipeline.py` instantiates and orders all 12 (or 13) pipeline layers:

```python
from astridr.security.pipeline import build_full_pipeline

pipeline = build_full_pipeline(
    telemetry=convex_handler,          # Optional ConvexHandler for telemetry
    audit_log_dir=Path("./audit"),     # Directory for audit JSONL files
    egress_allowed_domains=["api.openai.com"],
    egress_blocked_domains=["evil.com"],
    hitl_approval_callback=my_callback,  # async (action, details, ctx) -> bool
    hitl_block_on_escalation=True,
    dm_pairing_enabled=True,             # Include Layer 6
    dm_pairs_file=Path("config/dm_pairs.json"),
    persistence=supabase_persistence,    # For audit log replication
    profile_ids=["profile-abc"],         # For DLP scoping
)

# Process a message
result = await pipeline.process_inbound(message, context)
if not result.allowed:
    print(f"Blocked: {result.blocked_reason}")
```

The function builds the layer list in order (1-13), wires optional parameters into each layer's constructor, and returns a `SecurityPipeline` instance.

## Dependency Table

| Dependency | Version | Used By |
|------------|---------|---------|
| pydantic | >=2.0 | Config validation, data models |
| structlog | >=23.0 | Structured logging across all layers |
| aiohttp | >=3.9 | Async HTTP (egress control, webhooks) |
| aiosqlite | >=0.19 | DPAPI credential cache async SQLite |
| pywin32 | >=306 | Windows DPAPI encryption (optional, Windows-only) |

## Files in This Repository

```
astridr_security/
  hitl_gate.py          # Layer 13 -- HITL escalation
  rls_enforcement.py    # Layer 10 -- Row-Level Security
  audit_logger.py       # Layer 12 -- tamper-evident audit log
  dpapi_cache.py        # DPAPI-encrypted credential cache
  dm_pairing.py         # Layer 6 (optional) -- DM sender approval
  sensitive_action.py   # Layer 5 -- semantic intent flagging
pyproject.toml
README.md
```

## License

Private -- part of the Astridr framework.
