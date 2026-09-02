from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version

# HackerTarget's reverse-IP lookup: which domains currently resolve to this IP.
# Distinguishes a dedicated host (1 domain) from shared hosting / a reverse
# proxy fronting many sites (dozens). Free tier is no-key but rate limited
# (~50-100/day per source IP) - a quota message just degrades this to n/a.
API_URL = "https://api.hackertarget.com/reverseiplookup/"


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="Reverse IP", ok=True, verdict="unknown", category="context", summary="reverse-IP lookup is IPv4-only (HackerTarget)")

    try:
        resp = ctx.session.get(API_URL, params={"q": ip}, timeout=ctx.timeout)
    except requests.RequestException as e:
        return SourceResult(name="Reverse IP", ok=False, error=str(e), summary="request failed", category="context")

    if resp.status_code != 200:
        return SourceResult(name="Reverse IP", ok=False, error=f"HTTP {resp.status_code}", summary="lookup failed", category="context")

    body = resp.text.strip()
    low = body.lower()
    if "api count exceeded" in low or "too many requests" in low or "rate limit" in low:
        return SourceResult(name="Reverse IP", ok=False, error="rate limited", summary="HackerTarget free-tier quota hit", category="context")
    if not body or "no records found" in low or "no dns records" in low:
        return SourceResult(name="Reverse IP", ok=True, verdict="unknown", category="context", summary="no domains resolve to this IP")
    if "error" in low and "check your" in low:
        return SourceResult(name="Reverse IP", ok=False, error=body[:120], summary="lookup rejected", category="context")

    domains = sorted({
        d for line in body.splitlines()
        if (d := line.strip().lower()) and "." in d
        and not d.endswith((".in-addr.arpa", ".ip6.arpa"))
    })
    if not domains:
        return SourceResult(name="Reverse IP", ok=True, verdict="unknown", category="context", summary="no domains resolve to this IP")

    # HackerTarget caps the free-tier response at 500 rows; treat that as "many"
    # and don't bother listing a sample (it's just noise at that scale).
    capped = len(domains) >= 500
    if len(domains) == 1:
        kind = "dedicated host"
    elif len(domains) <= 5:
        kind = "a few domains"
    else:
        kind = "shared hosting / multi-tenant"

    if capped:
        summary = f"500+ domains — {kind}"
    elif len(domains) > 15:
        # a sample isn't informative at this scale, just the count
        summary = f"{len(domains)} domains — {kind}"
    else:
        shown = ", ".join(domains[:6]) + (f" … (+{len(domains) - 6} more)" if len(domains) > 6 else "")
        summary = f"{len(domains)} domain(s) — {kind}: {shown}"

    return SourceResult(
        name="Reverse IP",
        ok=True,
        verdict="unknown",
        category="context",
        summary=summary,
        details={"domain_count": len(domains), "capped": capped, "domains": domains[:200], "link": f"https://api.hackertarget.com/reverseiplookup/?q={ip}"},
    )
