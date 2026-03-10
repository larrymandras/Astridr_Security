"""16-layer security (12-layer pipeline + 4 complementary).

Pipeline layers (12 active, +1 optional DM pairing):
  1. pii_filter — detect and redact PII
  2. dlp_block — cross-profile data access prevention
  3. injection_defense — prompt injection detection
  4. blocklist — dangerous command blocking
  5. sensitive_action — flag credential access intents, block leaks
  6. dm_pairing — optional DM pair authorization
  7. secret_redactor — API key/secret redaction in outputs
  8. credential_access — controls access to secrets/credentials
  9. egress_control — whitelist-based outbound network control
  10. rls_enforcement — Row-Level Security for profile isolation
  11. output_filter — filters sensitive content from LLM output
  12. audit_logger — tamper-evident append-only audit logging
  13. hitl_gate — Human-In-The-Loop escalation for critical actions

Complementary security (outside pipeline):
  14. path_containment — filesystem path restriction for plugins/skills
  15. approval_gates — execution approval gate decisions
  16. budget_enforcement — per-profile LLM spend limit enforcement
  17. emergency_stop — user-triggered emergency halt of all agent activity
"""
