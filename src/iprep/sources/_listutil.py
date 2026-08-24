from __future__ import annotations

from ..context import Context


def fetch_ip_set(ctx: Context, cache_name: str, url: str, ttl: int, headers: dict[str, str] | None = None) -> set[str]:
    """Fetch (with caching) a plain newline-delimited IP list and return it as a set."""
    text = ctx.cache.get_text(cache_name, url, ttl, ctx.session, headers=headers)
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
