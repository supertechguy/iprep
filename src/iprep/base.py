from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VERDICTS = ("malicious", "suspicious", "clean", "unknown")


@dataclass
class SourceResult:
    """Normalized result from a single reputation/enrichment source."""

    name: str
    ok: bool
    verdict: str = "unknown"
    # 0-100, higher = worse. None when the source has no maliciousness opinion.
    score: float | None = None
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    # "reputation" sources feed the aggregate verdict; "context" sources are
    # shown for enrichment only (whois, ASN, reverse DNS, Tor membership...).
    category: str = "reputation"
