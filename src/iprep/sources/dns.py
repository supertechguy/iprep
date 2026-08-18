from __future__ import annotations

import dns.resolver
import dns.reversename

from ..base import SourceResult
from ..context import Context


def check(ip: str, ctx: Context) -> SourceResult:
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = ctx.dns_resolver.resolve(rev_name, "PTR")
        hostname = str(answers[0]).rstrip(".")
    except dns.resolver.NXDOMAIN:
        return SourceResult(name="Reverse DNS", ok=True, verdict="unknown", category="context", summary="no PTR record")
    except Exception as e:
        return SourceResult(name="Reverse DNS", ok=False, error=str(e), category="context", summary="lookup failed")

    forward_confirmed = False
    try:
        forward = ctx.dns_resolver.resolve(hostname, "A")
        forward_confirmed = ip in {str(r) for r in forward}
    except Exception:
        pass

    tag = "forward-confirmed" if forward_confirmed else "forward mismatch/unconfirmed"
    return SourceResult(
        name="Reverse DNS",
        ok=True,
        verdict="unknown",
        category="context",
        summary=f"PTR: {hostname} ({tag})",
        details={"hostname": hostname, "forward_confirmed": forward_confirmed},
    )
