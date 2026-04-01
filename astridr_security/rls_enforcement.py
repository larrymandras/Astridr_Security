"""RLS enforcement — Layer 10 of the 16-layer security stack.

Enforces Row-Level Security for profile data isolation.  Every
message is tagged with a profile scope and cross-profile data
references are rejected.
"""

from __future__ import annotations

import re

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

logger = structlog.get_logger()

# ─── Cross-profile detection ────────────────────────────────────────

# Pattern that matches profile IDs in text (e.g., profile_id=xxx, profileId:"xxx")
_PROFILE_REF_RE = re.compile(
    r"""(?:profile[_\-]?id)\s*[:=]\s*['"]?([a-zA-Z0-9_-]+)['"]?""",
    re.I,
)


def _extract_profile_references(text: str) -> list[str]:
    """Extract all profile ID references from text."""
    return _PROFILE_REF_RE.findall(text)


# ─── Query scoping ──────────────────────────────────────────────────


def scope_query(query: str, profile_id: str) -> str:
    """Add profile_id WHERE clause to a SQL query.

    If the query already contains a WHERE clause, appends with AND.
    Otherwise, adds a new WHERE clause before any ORDER BY, GROUP BY,
    LIMIT, or semicolon.
    """
    if not profile_id:
        raise ValueError("profile_id must not be empty")

    clause = f"profile_id = '{profile_id}'"

    # Already has WHERE — append with AND
    if re.search(r"\bWHERE\b", query, re.I):
        # Check if clause already present
        if re.search(rf"\bprofile_id\s*=\s*'{re.escape(profile_id)}'", query, re.I):
            return query
        # Insert AND clause after WHERE ... (before ORDER BY, GROUP BY, LIMIT, ;)
        return re.sub(
            r"(\bWHERE\b\s+)",
            rf"\1{clause} AND ",
            query,
            count=1,
            flags=re.I,
        )

    # No WHERE clause — add one
    # Find the best insertion point
    insert_re = re.compile(
        r"\b(ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET)\b|;",
        re.I,
    )
    match = insert_re.search(query)
    if match:
        pos = match.start()
        return query[:pos] + f"WHERE {clause} " + query[pos:]

    # No terminator found — append at end
    stripped = query.rstrip().rstrip(";")
    return f"{stripped} WHERE {clause}"


# ─── SecurityLayer implementation ────────────────────────────────────


class RLSEnforcementLayer(SecurityLayer):
    """Layer 10 — enforces Row-Level Security for profile data isolation.

    * **Inbound**: verifies profile_id is set in context.
    * **Outbound**: verifies response doesn't contain cross-profile references.
    """

    name: str = "rls_enforcement"

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Verify profile_id is set in context and tag message with scope."""
        events: list[dict] = []

        if not context.profile_id:
            events.append(
                {
                    "layer": self.name,
                    "severity": "critical",
                    "action": "blocked",
                    "profileId": "",
                    "details": {"reason": "missing profile_id in context"},
                }
            )
            return SecurityResult(
                allowed=False,
                message=message,
                events=events,
                blocked_reason="missing profile_id — RLS cannot be enforced",
            )

        # Check if message references other profiles
        refs = _extract_profile_references(message)
        foreign_refs = [r for r in refs if r != context.profile_id]
        if foreign_refs:
            events.append(
                {
                    "layer": self.name,
                    "severity": "warning",
                    "action": "flagged",
                    "profileId": context.profile_id,
                    "details": {
                        "reason": "cross-profile reference in inbound",
                        "foreign_profiles": foreign_refs,
                    },
                }
            )
            logger.warning(
                "rls_enforcement.cross_profile_inbound",
                profile_id=context.profile_id,
                foreign_profiles=foreign_refs,
            )

        return SecurityResult(allowed=True, message=message, events=events)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Verify response doesn't contain cross-profile data references."""
        events: list[dict] = []

        refs = _extract_profile_references(message)
        foreign_refs = [r for r in refs if r != context.profile_id]

        if foreign_refs:
            events.append(
                {
                    "layer": self.name,
                    "severity": "critical",
                    "action": "blocked",
                    "profileId": context.profile_id,
                    "details": {
                        "reason": "cross-profile data in outbound response",
                        "foreign_profiles": foreign_refs,
                    },
                }
            )
            logger.warning(
                "rls_enforcement.cross_profile_outbound",
                profile_id=context.profile_id,
                foreign_profiles=foreign_refs,
            )
            return SecurityResult(
                allowed=False,
                message=message,
                events=events,
                blocked_reason=f"cross-profile data leak: {', '.join(foreign_refs)}",
            )

        return SecurityResult(allowed=True, message=message, events=events)
