from __future__ import annotations

import dns.resolver

from ..base import SourceResult
from ..context import Context

# Team Cymru's free DNS-based ASN lookup service - no key, no rate limit
# problems in practice. https://team-cymru.com/community-services/ip-asn-mapping/


def check(ip: str, ctx: Context) -> SourceResult:
    octets = ip.split(".")
    if len(octets) != 4:
        return SourceResult(name="ASN", ok=False, error="IPv6 not supported by this check", summary="skipped", category="context")

    rev = ".".join(reversed(octets))
    try:
        origin_answers = ctx.dns_resolver.resolve(f"{rev}.origin.asn.cymru.com", "TXT")
    except dns.resolver.NXDOMAIN:
        return SourceResult(name="ASN", ok=True, verdict="unknown", category="context", summary="no ASN/BGP origin found (unannounced or reserved space)")
    except Exception as e:
        return SourceResult(name="ASN", ok=False, error=str(e), summary="lookup failed", category="context")

    origin_txt = str(origin_answers[0]).strip('"')
    parts = [p.strip() for p in origin_txt.split("|")]
    asn, prefix, cc, registry, allocated = (parts + [None] * 5)[:5]

    as_name = None
    if asn:
        asn_num = asn.split()[0]
        try:
            name_answers = ctx.dns_resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
            name_txt = str(name_answers[0]).strip('"')
            name_parts = [p.strip() for p in name_txt.split("|")]
            as_name = name_parts[-1] if name_parts else None
        except Exception:
            pass
    else:
        asn_num = "?"

    summary = f"AS{asn_num} {as_name or ''} — {prefix}, {cc}, {registry}".strip()
    return SourceResult(
        name="ASN",
        ok=True,
        verdict="unknown",
        category="context",
        summary=summary,
        details={"asn": asn, "prefix": prefix, "country": cc, "registry": registry, "allocated": allocated, "as_name": as_name},
    )
