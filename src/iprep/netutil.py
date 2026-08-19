from __future__ import annotations

import ipaddress

import dns.reversename


def ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip).version


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
