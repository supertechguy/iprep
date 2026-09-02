from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import lookup_origin

# Origin AS / BGP prefix via Team Cymru's free DNS service (netutil.lookup_origin).
# Pure context. The "is this whole AS bad" question is answered separately by
# the Spamhaus ASN-DROP source; here we just add a cheap anycast tell (a prefix
# announced from more than one origin AS).


def check(ip: str, ctx: Context) -> SourceResult:
    origin = lookup_origin(ip, ctx.dns_resolver)
    if origin is None:
        return SourceResult(name="ASN", ok=True, verdict="unknown", category="context", summary="no ASN/BGP origin found (unannounced or reserved space)")

    asn = origin["asn"] or "?"
    anycast = len(origin["origin_asns"]) > 1

    summary = f"AS{asn} {origin['as_name'] or ''} — {origin['prefix']}, {origin['country']}, {origin['registry']}".strip()
    if anycast:
        summary += f"  [announced from {len(origin['origin_asns'])} ASes ({', '.join(origin['origin_asns'])}) — likely anycast]"

    return SourceResult(
        name="ASN",
        ok=True,
        verdict="unknown",
        category="context",
        summary=summary,
        details={
            "asn": asn,
            "origin_asns": origin["origin_asns"],
            "prefix": origin["prefix"],
            "country": origin["country"],
            "registry": origin["registry"],
            "allocated": origin["allocated"],
            "as_name": origin["as_name"],
            "anycast_suspected": anycast,
        },
    )
