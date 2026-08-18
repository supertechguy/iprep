from __future__ import annotations

from dataclasses import dataclass

import dns.resolver
import requests

from .cache import Cache
from .config import Config


@dataclass
class Context:
    """Shared dependencies passed to every source module's check()."""

    config: Config
    cache: Cache
    session: requests.Session
    dns_resolver: dns.resolver.Resolver
    timeout: float = 15.0


def build_context(
    config: Config, force_refresh: bool = False, timeout: float = 15.0
) -> Context:
    session = requests.Session()
    session.headers["User-Agent"] = "iprep-cli/0.1 (+https://github.com/)"

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    return Context(
        config=config,
        cache=Cache(force_refresh=force_refresh),
        session=session,
        dns_resolver=resolver,
        timeout=timeout,
    )
