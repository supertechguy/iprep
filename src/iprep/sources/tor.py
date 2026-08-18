from __future__ import annotations

from ..base import SourceResult
from ..context import Context

# The Tor Project's own bulk exit list - the standard no-key endpoint many
# tools use for this exact check.
FEED_URL = "https://check.torproject.org/torbulkexitlist"
CACHE_NAME = "tor_exit_nodes.txt"
CACHE_TTL = 3600


def check(ip: str, ctx: Context) -> SourceResult:
    try:
        text = ctx.cache.get_text(CACHE_NAME, FEED_URL, CACHE_TTL, ctx.session)
    except Exception as e:
        return SourceResult(name="Tor Exit Node", ok=False, error=str(e), category="context", summary="could not fetch Tor exit list")

    ips = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
    hit = ip in ips

    return SourceResult(
        name="Tor Exit Node",
        ok=True,
        verdict="unknown",
        category="context",
        summary="is a known Tor exit node" if hit else "not a Tor exit node",
        details={"is_tor_exit": hit, "list_size": len(ips)},
    )
