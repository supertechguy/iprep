from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version
from ._listutil import fetch_ip_set

# abuse.ch Feodo Tracker: active banking-trojan/botnet C2 server IPs
# (Dridex, Emotet, QakBot, etc). Small and tightly-scoped (typically single
# digits to low hundreds of entries) - very low false-positive rate since
# it's specifically confirmed, currently-active C2 infrastructure rather
# than a broad "seen doing something bad at some point" report. No auth
# required. https://feodotracker.abuse.ch/
FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
CACHE_NAME = "feodotracker.txt"
CACHE_TTL = 3600


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="Feodo Tracker", ok=True, verdict="unknown", score=None, summary="Feodo Tracker is IPv4-only")

    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL)
    except Exception as e:
        return SourceResult(name="Feodo Tracker", ok=False, error=str(e), summary="could not fetch Feodo Tracker feed")

    hit = ip in ips
    return SourceResult(
        name="Feodo Tracker",
        ok=True,
        verdict="malicious" if hit else "clean",
        score=100.0 if hit else 0.0,
        summary="active botnet C2 server (Feodo Tracker)" if hit else "not a known active C2 server",
        details={"list_size": len(ips), "link": "https://feodotracker.abuse.ch/browse/"},
    )
