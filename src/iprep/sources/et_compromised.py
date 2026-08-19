from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version
from ._listutil import fetch_ip_set

# Proofpoint/Emerging Threats' open "compromised hosts" ruleset - a classic
# IDS feed (free tier), updated regularly. IPv4 only.
FEED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
CACHE_NAME = "et_compromised.txt"
CACHE_TTL = 6 * 3600


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="Emerging Threats", ok=True, verdict="unknown", score=None, summary="ET compromised-hosts feed is IPv4-only")

    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL)
    except Exception as e:
        return SourceResult(name="Emerging Threats", ok=False, error=str(e), summary="could not fetch ET compromised-hosts feed")

    hit = ip in ips
    return SourceResult(
        name="Emerging Threats",
        ok=True,
        verdict="malicious" if hit else "clean",
        score=100.0 if hit else 0.0,
        summary="on ET compromised-hosts list" if hit else "not on ET compromised-hosts list",
        details={"list_size": len(ips), "link": "https://rules.emergingthreats.net/"},
    )
