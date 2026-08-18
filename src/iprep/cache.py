from __future__ import annotations

import os
import time
from pathlib import Path

import requests

CACHE_DIR = Path(os.environ.get("IPREP_CACHE_DIR", Path.home() / ".cache" / "iprep"))


class Cache:
    """Simple file-backed cache for the blocklist/list-based sources.

    These feeds (FireHOL, Talos, Tor exit list) are large static text files
    published for anyone to pull. Re-downloading them on every single `iprep`
    invocation would be slow and impolite, so we cache to disk with a TTL and
    fall back to a stale copy if a refresh fails.
    """

    def __init__(self, cache_dir: Path = CACHE_DIR, force_refresh: bool = False):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.force_refresh = force_refresh

    def get_text(
        self, name: str, url: str, ttl_seconds: int, session: requests.Session
    ) -> str:
        path = self.cache_dir / name
        if not self.force_refresh and path.exists():
            age = time.time() - path.stat().st_mtime
            if age < ttl_seconds:
                return path.read_text()
        try:
            resp = session.get(url, timeout=30)
            resp.raise_for_status()
        except requests.RequestException:
            if path.exists():
                return path.read_text()
            raise
        path.write_text(resp.text)
        return resp.text
