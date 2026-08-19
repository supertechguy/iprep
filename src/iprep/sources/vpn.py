from __future__ import annotations

import ipaddress

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version

# X4BNet's community-maintained, regularly-updated VPN/datacenter IP range
# lists (github.com/X4BNet/lists_vpn). Two tiers:
#   "vpn"        - high-confidence, known commercial VPN provider ranges.
#   "datacenter" - a broader superset that also covers general hosting/cloud/
#                  proxy infrastructure. Useful for "this isn't a residential
#                  connection" but plenty of datacenter IPs are ordinary cloud
#                  servers, not VPN exits, so it's a softer signal than "vpn".
# Using a VPN isn't inherently malicious (same reasoning as the Tor check),
# so this stays a context source rather than feeding the malicious verdict.
LISTS = {
    4: {
        "vpn": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
        "datacenter": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
    },
    6: {
        "vpn": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt",
        "datacenter": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt",
    },
}
CACHE_TTL = 24 * 3600


def _parse_networks(text: str) -> list:
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets


def check(ip: str, ctx: Context) -> SourceResult:
    version = ip_version(ip)
    addr = ipaddress.ip_address(ip)
    urls = LISTS[version]

    hits: list[str] = []
    errors: list[str] = []
    for tier, url in urls.items():
        try:
            text = ctx.cache.get_text(f"x4bnet_{tier}_v{version}.txt", url, CACHE_TTL, ctx.session)
        except Exception as e:
            errors.append(f"{tier}: {e}")
            continue
        nets = _parse_networks(text)
        if any(addr in n for n in nets):
            hits.append(tier)

    if not hits and errors and len(errors) == len(urls):
        return SourceResult(name="VPN/Proxy", ok=False, error="; ".join(errors), summary="could not fetch VPN/datacenter lists", category="context")

    if "vpn" in hits:
        summary = "known VPN provider exit node"
    elif "datacenter" in hits:
        summary = "datacenter/hosting IP (could be a VPN, proxy, cloud server, or scraper - not residential)"
    else:
        summary = "not on any known VPN/datacenter range"

    return SourceResult(
        name="VPN/Proxy",
        ok=True,
        verdict="unknown",
        category="context",
        summary=summary,
        details={"hits": hits, "errors": errors, "link": "https://github.com/X4BNet/lists_vpn"},
    )
