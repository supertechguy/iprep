from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version
from ._listutil import fetch_ip_set

# The Tor Project's own bulk exit list - the standard no-key endpoint many
# tools use for this exact check. Confirmed IPv4-only (no IPv6 entries as of
# this writing); Tor relays do announce some IPv6 addresses but this
# particular feed doesn't carry them.
FEED_URL = "https://check.torproject.org/torbulkexitlist"
CACHE_NAME = "tor_exit_nodes.txt"
CACHE_TTL = 3600


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(
            name="Tor Exit Node", ok=True, verdict="unknown", score=None, category="context",
            summary="the Tor bulk exit list is IPv4-only; can't check this IPv6 address",
        )

    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL)
    except Exception as e:
        return SourceResult(name="Tor Exit Node", ok=False, error=str(e), category="context", summary="could not fetch Tor exit list")

    hit = ip in ips
    return SourceResult(
        name="Tor Exit Node",
        ok=True,
        verdict="unknown",
        category="context",
        summary="is a known Tor exit node" if hit else "not a Tor exit node",
        details={"is_tor_exit": hit, "list_size": len(ips)},
    )
