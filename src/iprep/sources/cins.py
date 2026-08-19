from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version
from ._listutil import fetch_ip_set

# CINS Army ("bad guys") list - a long-established, widely used (Snort/
# Suricata community) list of IPs with a poor CI-Army threat score based on
# observed hostile activity. IPv4 only.
FEED_URL = "http://cinsscore.com/list/ci-badguys.txt"
CACHE_NAME = "cins_army.txt"
CACHE_TTL = 6 * 3600


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="CINS Army", ok=True, verdict="unknown", score=None, summary="CINS Army list is IPv4-only")

    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL)
    except Exception as e:
        return SourceResult(name="CINS Army", ok=False, error=str(e), summary="could not fetch CINS Army list")

    hit = ip in ips
    return SourceResult(
        name="CINS Army",
        ok=True,
        verdict="malicious" if hit else "clean",
        score=100.0 if hit else 0.0,
        summary="present on CINS Army bad-guys list" if hit else "not on CINS Army bad-guys list",
        details={"list_size": len(ips), "link": "https://cinsscore.com/#list"},
    )
