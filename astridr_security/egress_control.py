"""Egress control — Layer 9 of the security pipeline.

Controls outbound network requests using a domain whitelist.
Messages that reference URLs outside the allowed list are blocked.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import structlog

from astridr.security.pipeline import (
    SecurityContext,
    SecurityLayer,
    SecurityResult,
)

logger = structlog.get_logger()

# ─── URL extraction ──────────────────────────────────────────────────

_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.I,
)


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP(S) URLs from *text*."""
    return _URL_RE.findall(text)


def extract_domain(url: str) -> str:
    """Extract the domain (hostname) from a URL."""
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


# ─── Default allowed domains ─────────────────────────────────────────

DEFAULT_ALLOWED_DOMAINS: list[str] = [
    "api.openai.com",
    "api.anthropic.com",
    "openrouter.ai",
    "api.github.com",
    "github.com",
    "api.telegram.org",
    "slack.com",
    "localhost",
    "127.0.0.1",
]


# ─── SecurityLayer implementation ──────────────────────────────────────


class EgressControlLayer(SecurityLayer):
    """Layer 9 — controls outbound network requests.

    Uses a domain whitelist.  Any URL whose domain is not in the
    allowed list is blocked.  A separate blocked-domains list can
    override the whitelist for extra safety.
    """

    name: str = "egress_control"

    def __init__(
        self,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
    ) -> None:
        self._allowed: set[str] = {
            d.lower() for d in (allowed_domains or DEFAULT_ALLOWED_DOMAINS)
        }
        self._blocked: set[str] = {
            d.lower() for d in (blocked_domains or [])
        }

    # ── public helpers ─────────────────────────────────────────────

    def is_allowed(self, url: str) -> bool:
        """Check if *url*'s domain is in the allowed list and not blocked."""
        domain = extract_domain(url)
        if not domain:
            return False
        if domain in self._blocked:
            return False
        # Check exact match and parent-domain match
        if domain in self._allowed:
            return True
        # Allow subdomains of allowed domains
        for allowed in self._allowed:
            if domain.endswith("." + allowed):
                return True
        return False

    # ── layer interface ────────────────────────────────────────────

    async def process_inbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Inbound: pass through (egress control only checks outbound)."""
        return SecurityResult(allowed=True, message=message)

    async def process_outbound(
        self, message: str, context: SecurityContext
    ) -> SecurityResult:
        """Extract URLs from message and check against whitelist."""
        urls = extract_urls(message)
        if not urls:
            return SecurityResult(allowed=True, message=message)

        disallowed: list[str] = []
        for url in urls:
            if not self.is_allowed(url):
                disallowed.append(url)

        if disallowed:
            events: list[dict] = [
                {
                    "layer": self.name,
                    "severity": "critical",
                    "action": "blocked",
                    "profileId": context.profile_id,
                    "details": {
                        "reason": "disallowed egress domain",
                        "urls": disallowed,
                    },
                }
            ]
            logger.warning(
                "egress_control.blocked",
                urls=disallowed,
                profile_id=context.profile_id,
            )
            return SecurityResult(
                allowed=False,
                message=message,
                events=events,
                blocked_reason=f"egress blocked: {', '.join(disallowed)}",
            )

        return SecurityResult(allowed=True, message=message)
