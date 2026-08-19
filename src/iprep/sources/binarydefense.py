from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version
from ._listutil import fetch_ip_set

# Binary Defense's honeypot-derived IP banlist - free, no auth.
FEED_URL = "https://www.binarydefense.com/banlist.txt"
CACHE_NAME = "binarydefense.txt"
CACHE_TTL = 6 * 3600


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="Binary Defense", ok=True, verdict="unknown", score=None, summary="Binary Defense banlist is IPv4-only")

    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL)
    except Exception as e:
        return SourceResult(name="Binary Defense", ok=False, error=str(e), summary="could not fetch Binary Defense banlist")

    hit = ip in ips
    return SourceResult(
        name="Binary Defense",
        ok=True,
        verdict="malicious" if hit else "clean",
        score=100.0 if hit else 0.0,
        summary="on Binary Defense's honeypot-derived banlist" if hit else "not on Binary Defense banlist",
        details={"list_size": len(ips), "link": "https://www.binarydefense.com/banlist.txt"},
    )
