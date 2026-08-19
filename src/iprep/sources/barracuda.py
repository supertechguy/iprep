from __future__ import annotations

import dns.resolver

from ..base import SourceResult
from ..context import Context
from ..netutil import dnsbl_query, ip_version

# Barracuda Reputation Block List - free DNSBL, works without pre-
# registration for ordinary query volumes (verified live). Single return
# code (127.0.0.2 = listed), unlike Spamhaus's multiple sub-codes.
# IPv6 support unconfirmed, so IPv6 is skipped rather than risking a
# false "clean" from a zone that silently doesn't cover it.
# http://barracudacentral.org/rbl
ZONE = "b.barracudacentral.org"


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="Barracuda RBL", ok=True, verdict="unknown", score=None, summary="Barracuda RBL IPv6 support is unconfirmed; skipped to avoid a false clean")

    query = dnsbl_query(ip, ZONE)
    try:
        ctx.dns_resolver.resolve(query, "A")
    except dns.resolver.NXDOMAIN:
        return SourceResult(name="Barracuda RBL", ok=True, verdict="clean", score=0.0, summary="not listed on Barracuda RBL", details={"link": "http://barracudacentral.org/rbl/removal-request"})
    except dns.resolver.NoNameservers:
        return SourceResult(name="Barracuda RBL", ok=False, error="query blocked/rate-limited", summary="resolver may be blocked; Barracuda asks high-volume users to register at barracudacentral.org")
    except Exception as e:
        return SourceResult(name="Barracuda RBL", ok=False, error=str(e), summary="lookup failed")

    return SourceResult(
        name="Barracuda RBL",
        ok=True,
        verdict="malicious",
        score=100.0,
        summary="listed on Barracuda Reputation Block List",
        details={"link": "http://barracudacentral.org/rbl/removal-request"},
    )
