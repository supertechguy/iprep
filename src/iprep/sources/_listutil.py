from __future__ import annotations

from ..context import Context


def fetch_ip_set(ctx: Context, cache_name: str, url: str, ttl: int) -> set[str]:
    """Fetch (with caching) a plain newline-delimited IP list and return it as a set."""
    text = ctx.cache.get_text(cache_name, url, ttl, ctx.session)
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
