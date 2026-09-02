from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context
from ..netutil import cached_origin

# RPKI route-origin validation via RIPEstat. Tells you whether the BGP
# announcement this IP is reachable through is cryptographically authorised by
# the prefix holder:
#   valid   - a ROA exists and matches the origin AS (good hygiene)
#   invalid - a ROA exists but the announcement violates it: wrong origin AS or
#             a more-specific than allowed. Can be a hijack, a leak, or just a
#             stale ROA - worth a look either way.
#   unknown - no ROA covers this prefix (still the common case; not alarming)
# Context only: an invalid route doesn't by itself mean the IP is malicious.
API_URL = "https://stat.ripe.net/data/rpki-validation/data.json"


def check(ip: str, ctx: Context) -> SourceResult:
    origin = cached_origin(ip, ctx)
    if origin is None or not origin["asn"] or not origin["prefix"]:
        return SourceResult(name="RPKI", ok=True, verdict="unknown", category="context", summary="no announced route to validate")

    try:
        resp = ctx.session.get(
            API_URL,
            params={"resource": f"AS{origin['asn']}", "prefix": origin["prefix"]},
            timeout=ctx.timeout,
        )
    except requests.RequestException as e:
        return SourceResult(name="RPKI", ok=False, error=str(e), summary="request failed", category="context")

    if resp.status_code != 200:
        return SourceResult(name="RPKI", ok=False, error=f"HTTP {resp.status_code}", summary="validation lookup failed", category="context")

    try:
        data = resp.json().get("data", {}) or {}
    except ValueError:
        return SourceResult(name="RPKI", ok=False, error="unparseable response", summary="validation lookup failed", category="context")

    status = (data.get("status") or "unknown").lower()
    route = f"{origin['prefix']} via AS{origin['asn']}"
    blurb = {
        "valid": f"RPKI-valid — {route} is authorised by a matching ROA",
        "invalid": f"RPKI-INVALID — {route} violates the prefix's ROA (possible hijack/leak or a stale ROA)",
        "unknown": f"RPKI-unknown — no ROA covers {origin['prefix']} (common; not a red flag)",
    }.get(status, f"RPKI status: {status} ({route})")

    return SourceResult(
        name="RPKI",
        ok=True,
        verdict="unknown",
        category="context",
        summary=blurb,
        details={
            "status": status,
            "prefix": origin["prefix"],
            "asn": origin["asn"],
            "validating_roas": data.get("validating_roas") or [],
            "link": f"https://stat.ripe.net/{origin['prefix']}",
        },
    )
