from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version

# Passive DNS via OTX: domains that have historically resolved to this IP.
# Uses the same unauthenticated OTX endpoint family as the reputation source
# (an optional OTX key just raises the rate limit). Context only - hosting
# domains isn't malicious, but "40 lookalike domains all pointed here last
# month" is exactly the kind of thing you want to see next to a verdict.
API_URL = "https://otx.alienvault.com/api/v1/indicators/{family}/{ip}/passive_dns"


def check(ip: str, ctx: Context) -> SourceResult:
    family = "IPv6" if ip_version(ip) == 6 else "IPv4"
    headers = {}
    if ctx.config.otx_api_key:
        headers["X-OTX-API-Key"] = ctx.config.otx_api_key

    try:
        resp = ctx.session.get(API_URL.format(family=family, ip=ip), headers=headers, timeout=ctx.timeout)
    except requests.Timeout:
        return SourceResult(name="Passive DNS", ok=False, error="timed out", summary="OTX passive-DNS is often slow — retry, or raise --timeout", category="context")
    except requests.RequestException as e:
        return SourceResult(name="Passive DNS", ok=False, error=str(e), summary="request failed", category="context")

    if resp.status_code == 429:
        return SourceResult(name="Passive DNS", ok=False, error="rate limited", summary="OTX rate limit — optional key raises it", category="context")
    if resp.status_code != 200:
        return SourceResult(name="Passive DNS", ok=False, error=f"HTTP {resp.status_code}", summary="lookup failed", category="context")

    try:
        records = resp.json().get("passive_dns", []) or []
    except ValueError:
        return SourceResult(name="Passive DNS", ok=False, error="unparseable response", summary="lookup failed", category="context")

    hostnames = sorted({r["hostname"].rstrip(".").lower() for r in records if r.get("hostname")})
    if not hostnames:
        return SourceResult(name="Passive DNS", ok=True, verdict="unknown", category="context", summary="no passive-DNS records (no domain has been seen resolving here)")

    last_seen = max((r.get("last") or "" for r in records), default="")
    first_seen = min((r.get("first") or "" for r in records if r.get("first")), default="")
    shown = ", ".join(hostnames[:8]) + (f" … (+{len(hostnames) - 8} more)" if len(hostnames) > 8 else "")
    when = f"; last seen {last_seen[:10]}" if last_seen else ""
    return SourceResult(
        name="Passive DNS",
        ok=True,
        verdict="unknown",
        category="context",
        summary=f"{len(hostnames)} domain(s) historically resolved here{when}: {shown}",
        details={
            "hostname_count": len(hostnames),
            "hostnames": hostnames[:200],
            "first_seen": first_seen or None,
            "last_seen": last_seen or None,
            "link": f"https://otx.alienvault.com/indicator/ip/{ip}",
        },
    )
