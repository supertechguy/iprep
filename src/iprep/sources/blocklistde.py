from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ._listutil import fetch_ip_set

# Blocklist.de - crowdsourced fail2ban-style abuse reports (SSH/mail/web
# bruteforce, exploit attempts) contributed by a large network of servers.
# Unlike most of the other blocklist-style sources here, this one carries a
# meaningful number of real IPv6 entries too.
FEED_URL = "https://lists.blocklist.de/lists/all.txt"
CACHE_NAME = "blocklist_de.txt"
CACHE_TTL = 6 * 3600


def check(ip: str, ctx: Context) -> SourceResult:
    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL)
    except Exception as e:
        return SourceResult(name="Blocklist.de", ok=False, error=str(e), summary="could not fetch Blocklist.de list")

    hit = ip in ips
    return SourceResult(
        name="Blocklist.de",
        ok=True,
        verdict="malicious" if hit else "clean",
        score=100.0 if hit else 0.0,
        summary="reported to Blocklist.de (SSH/mail/web abuse)" if hit else "not reported to Blocklist.de",
        details={"list_size": len(ips), "link": "https://www.blocklist.de/en/index.html"},
    )
