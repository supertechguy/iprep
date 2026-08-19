from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version

# stamparm/ipsum aggregates dozens of public blocklists and reports how many
# distinct feeds flag each IP - a useful "how many other lists agree" meta
# signal that would otherwise mean manually cross-referencing many sources
# by hand. IPv4 only. https://github.com/stamparm/ipsum
FEED_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
CACHE_NAME = "ipsum.txt"
CACHE_TTL = 12 * 3600


def _looks_like_ipsum(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    first_line = next((line for line in stripped.splitlines() if line.strip() and not line.startswith("#")), "")
    return "\t" in first_line


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="ipsum", ok=True, verdict="unknown", score=None, summary="ipsum is IPv4-only")

    try:
        text = ctx.cache.get_text(CACHE_NAME, FEED_URL, CACHE_TTL, ctx.session, validate=_looks_like_ipsum)
    except Exception as e:
        return SourceResult(name="ipsum", ok=False, error=str(e), summary="could not fetch ipsum feed")

    count = 0
    total_entries = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        total_entries += 1
        parts = line.split("\t")
        if len(parts) == 2 and parts[0] == ip:
            count = int(parts[1])

    if count == 0:
        return SourceResult(
            name="ipsum", ok=True, verdict="clean", score=0.0,
            summary=f"not present among the {total_entries} flagged IPs ipsum aggregates",
            details={"link": "https://github.com/stamparm/ipsum"},
        )

    # ipsum's count is how many distinct source blocklists flagged the IP (no
    # fixed max, but double digits is rare) - scale gently rather than
    # jumping straight to 100 on a single-list hit.
    score = min(100.0, count * 12.0)
    verdict = "malicious" if count >= 4 else "suspicious"
    return SourceResult(
        name="ipsum",
        ok=True,
        verdict=verdict,
        score=score,
        summary=f"flagged by {count} distinct blocklist(s) aggregated by ipsum",
        details={"hit_count": count, "link": "https://github.com/stamparm/ipsum"},
    )
