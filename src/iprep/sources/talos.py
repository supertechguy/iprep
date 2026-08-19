from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version
from ._listutil import fetch_ip_set

# Cisco Talos does not publish a public REST API; their web reputation lookup
# (talosintelligence.com/reputation_center) is a JS-rendered page not meant
# for scraping. Instead we use the Talos-curated Snort IP blocklist feed,
# which is the same data source Snort/Suricata deployments pull from.
# Confirmed IPv4-only.
FEED_URL = "https://snort.org/downloads/ip-block-list"
CACHE_NAME = "talos_ip_blacklist.txt"
CACHE_TTL = 6 * 3600  # feed updates roughly hourly upstream; 6h local TTL is plenty


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="Talos", ok=True, verdict="unknown", score=None, summary="Talos/Snort blacklist feed is IPv4-only")

    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL)
    except Exception as e:
        return SourceResult(name="Talos", ok=False, error=str(e), summary="could not fetch Talos/Snort blacklist feed")

    hit = ip in ips

    return SourceResult(
        name="Talos",
        ok=True,
        verdict="malicious" if hit else "clean",
        score=100.0 if hit else 0.0,
        summary="present on Talos/Snort IP blacklist" if hit else "not on Talos/Snort IP blacklist",
        details={"list_size": len(ips), "link": "https://talosintelligence.com/reputation_center"},
    )
