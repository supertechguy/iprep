from __future__ import annotations

import ipaddress

from ..base import SourceResult
from ..context import Context

# FireHOL's own tiered aggregates: level1 is curated for a near-zero false
# positive rate, level2/3 trade some precision for broader coverage.
# https://iplists.firehol.org/
LISTS = {
    "firehol_level1": (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "high-confidence aggregate (very low false-positive rate)",
    ),
    "firehol_level2": (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "medium-confidence aggregate",
    ),
    "firehol_level3": (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
        "broad/aggressive aggregate, more false positives",
    ),
}
CACHE_TTL = 24 * 3600


def _parse_networks(text: str) -> list[ipaddress._BaseNetwork]:
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
    addr = ipaddress.ip_address(ip)
    hits: list[tuple[str, str]] = []
    errors: list[str] = []
    total_entries = 0

    for list_name, (url, desc) in LISTS.items():
        try:
            text = ctx.cache.get_text(f"{list_name}.netset", url, CACHE_TTL, ctx.session)
        except Exception as e:
            errors.append(f"{list_name}: {e}")
            continue
        nets = _parse_networks(text)
        total_entries += len(nets)
        if any(addr in n for n in nets):
            hits.append((list_name, desc))

    if not hits and errors and len(errors) == len(LISTS):
        return SourceResult(name="FireHOL", ok=False, error="; ".join(errors), summary="could not fetch any FireHOL lists")

    if hits:
        verdict = "malicious" if any(name == "firehol_level1" for name, _ in hits) else "suspicious"
        score = 100.0 if verdict == "malicious" else 60.0
        summary = "present on: " + ", ".join(f"{n} ({d})" for n, d in hits)
    else:
        verdict, score = "clean", 0.0
        summary = f"not present on {len(LISTS)} FireHOL aggregate lists ({total_entries} entries checked)"

    return SourceResult(
        name="FireHOL",
        ok=True,
        verdict=verdict,
        score=score,
        summary=summary,
        details={"hits": [n for n, _ in hits], "errors": errors, "link": "https://iplists.firehol.org/"},
    )
