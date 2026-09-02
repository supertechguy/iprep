from __future__ import annotations

import ipaddress

import dns.resolver
import dns.reversename


def ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip).version


def lookup_origin(ip: str, resolver: dns.resolver.Resolver) -> dict | None:
    """Team Cymru DNS-based origin/ASN lookup, shared by every source that
    needs to know the announcing AS or BGP prefix (asn, rpki, cloud fallback).

    Returns a dict with: asn (first origin, str), origin_asns (list, >1 means
    the prefix is announced from multiple ASes - often anycast), prefix,
    country, registry, allocated, as_name. None if the IP has no announced
    origin (unrouted/reserved).
    """
    zone = "origin.asn.cymru.com" if ip_version(ip) == 4 else "origin6.asn.cymru.com"
    query = dnsbl_query(ip, zone)
    try:
        answers = resolver.resolve(query, "TXT")
    except dns.resolver.NXDOMAIN:
        return None
    except Exception:
        return None

    txt = str(answers[0]).strip('"')
    parts = [p.strip() for p in txt.split("|")]
    asn_field, prefix, cc, registry, allocated = (parts + [None] * 5)[:5]
    origin_asns = (asn_field or "").split()
    asn = origin_asns[0] if origin_asns else None

    as_name = None
    if asn:
        try:
            name_answers = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
            name_parts = [p.strip() for p in str(name_answers[0]).strip('"').split("|")]
            as_name = name_parts[-1] if name_parts else None
        except Exception:
            pass

    return {
        "asn": asn,
        "origin_asns": origin_asns,
        "prefix": prefix,
        "country": cc,
        "registry": registry,
        "allocated": allocated,
        "as_name": as_name,
    }


def dnsbl_query(ip: str, zone: str) -> str:
    """Build a DNSBL/RBL-style query name for an IPv4 or IPv6 address against
    `zone`, e.g. dnsbl_query("1.2.3.4", "zen.spamhaus.org") ->
    "4.3.2.1.zen.spamhaus.org".

    For IPv6 this reuses dnspython's ip6.arpa nibble-reversal (the standard
    construction most IPv6-aware DNSBLs use) and just re-roots it at `zone`
    instead of ip6.arpa.
    """
    if ip_version(ip) == 4:
        return ".".join(reversed(ip.split("."))) + "." + zone

    reversed_name = str(dns.reversename.from_address(ip))  # "<32 nibbles>.ip6.arpa."
    nibbles = reversed_name[: -len("ip6.arpa.")]
    return f"{nibbles}{zone}"
