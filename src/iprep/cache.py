from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable

import requests

CACHE_DIR = Path(os.environ.get("IPREP_CACHE_DIR", Path.home() / ".cache" / "iprep"))


class BadFeedContent(Exception):
    """Raised when a fetched feed fails validation (e.g. a bot-challenge/error
    page came back instead of the expected plaintext list)."""


def looks_like_plaintext_list(text: str) -> bool:
    """Cheap sanity check that a response is the plain IP/CIDR list we asked
    for and not an HTML error/challenge page. These feeds occasionally sit
    behind bot protection that serves an HTML page (still HTTP 200) instead
    of the real content - trusting that blindly would cache garbage for the
    full TTL and silently turn every lookup against it into a false "clean".
    """
    stripped = text.strip()
    if not stripped:
        return False
    first_line = next((line.strip() for line in stripped.splitlines() if line.strip() and not line.strip().startswith("#")), "")
    return not first_line.lstrip().startswith("<")


class Cache:
    """Simple file-backed cache for the blocklist/list-based sources.

    These feeds (FireHOL, Talos, Tor exit list, etc.) are large static text
    files published for anyone to pull. Re-downloading them on every single
    `iprep` invocation would be slow and impolite, so we cache to disk with a
    TTL and fall back to a stale copy if a refresh fails or fails validation.
    """

    def __init__(self, cache_dir: Path = CACHE_DIR, force_refresh: bool = False):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.force_refresh = force_refresh

    def get_text(
        self,
        name: str,
        url: str,
        ttl_seconds: int,
        session: requests.Session,
        validate: Callable[[str], bool] = looks_like_plaintext_list,
    ) -> str:
        path = self.cache_dir / name
        if not self.force_refresh and path.exists():
            age = time.time() - path.stat().st_mtime
            if age < ttl_seconds:
                return path.read_text()
        try:
            resp = session.get(url, timeout=30)
            resp.raise_for_status()
            if not validate(resp.text):
                raise BadFeedContent(f"fetched content from {url} doesn't look like the expected list (possibly blocked/challenged)")
        except (requests.RequestException, BadFeedContent):
            if path.exists():
                return path.read_text()
            raise
        path.write_text(resp.text)
        return resp.text
