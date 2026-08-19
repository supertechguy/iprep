from __future__ import annotations

import ipaddress

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version

# SANS Internet Storm Center / DShield "recommended block list" - the top
# ~20 attacking /24 netblocks over the last 3 days, from their global
# sensor network. Small and IPv4-only, but high-signal (actively attacking
# right now, not a historical archive). Format is tab-delimited rows:
# start_ip, end_ip, subnet_bits, attack_count, network_name, country, contact.
# https://isc.sans.edu/ipinfo.html
FEED_URL = "https://feeds.dshield.org/block.txt"
CACHE_NAME = "dshield_block.txt"
CACHE_TTL = 3 * 3600


def _parse_entries(text: str) -> list[tuple[ipaddress.IPv4Network, str]]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        start_ip, subnet_bits, attack_count = parts[0], parts[2], parts[3]
        try:
            net = ipaddress.ip_network(f"{start_ip}/{subnet_bits}", strict=False)
        except ValueError:
            continue
        entries.append((net, attack_count))
    return entries


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="DShield", ok=True, verdict="unknown", score=None, summary="DShield block list is IPv4-only")

    try:
        text = ctx.cache.get_text(CACHE_NAME, FEED_URL, CACHE_TTL, ctx.session)
    except Exception as e:
        return SourceResult(name="DShield", ok=False, error=str(e), summary="could not fetch DShield block list")

    addr = ipaddress.ip_address(ip)
    entries = _parse_entries(text)
    hit = next(((net, count) for net, count in entries if addr in net), None)

    if hit:
        net, count = hit
        return SourceResult(
            name="DShield",
            ok=True,
            verdict="malicious",
            score=100.0,
            summary=f"inside a top-attacking netblock per DShield ({net}, ~{count} reported attack sources)",
            details={"netblock": str(net), "attack_count": count, "link": "https://isc.sans.edu/ipinfo.html"},
        )

    return SourceResult(
        name="DShield",
        ok=True,
        verdict="clean",
        score=0.0,
        summary=f"not inside any of DShield's {len(entries)} currently-listed top-attacking netblocks",
        details={"link": "https://isc.sans.edu/ipinfo.html"},
    )
