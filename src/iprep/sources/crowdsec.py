from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

# CrowdSec CTI - crowd-sourced, near-real-time attack data from CrowdSec's
# sensor network. Free tier is 120 lookups/month (confirmed from their
# docs), key required (confirmed mandatory - unauthenticated requests get
# a 403). https://app.crowdsec.net
API_URL = "https://cti.api.crowdsec.net/v2/smoke/{ip}"
SETUP_HINT = "Free key (120 lookups/month) at https://app.crowdsec.net then run `iprep keys set crowdsec`."

# CrowdSec's own reputation categories, worst to best; anything else
# (a value they add later, or a typo on our part) falls through to "unknown"
# rather than being silently miscategorized.
REPUTATION_VERDICTS = {
    "malicious": ("malicious", 90.0),
    "suspicious": ("suspicious", 50.0),
    "known": ("clean", 0.0),
    "safe": ("clean", 0.0),
}


def check(ip: str, ctx: Context) -> SourceResult:
    key = ctx.config.crowdsec_api_key
    if not key:
        return SourceResult(name="CrowdSec CTI", ok=False, error="no API key configured", summary=SETUP_HINT)

    try:
        resp = ctx.session.get(API_URL.format(ip=ip), headers={"x-api-key": key}, timeout=ctx.timeout)
    except requests.RequestException as e:
        return SourceResult(name="CrowdSec CTI", ok=False, error=str(e), summary="request failed")

    if resp.status_code == 403:
        return SourceResult(name="CrowdSec CTI", ok=False, error="invalid API key", summary=SETUP_HINT)
    if resp.status_code == 429:
        return SourceResult(name="CrowdSec CTI", ok=False, error="rate limited", summary="free tier is 120 lookups/month; try again later")
    if resp.status_code == 404:
        return SourceResult(name="CrowdSec CTI", ok=True, verdict="unknown", score=0.0, summary="no CrowdSec CTI data for this IP")
    if resp.status_code != 200:
        return SourceResult(name="CrowdSec CTI", ok=False, error=f"HTTP {resp.status_code}", summary=resp.text[:200])

    d = resp.json()
    reputation = d.get("reputation", "unknown")
    confidence = d.get("confidence", "unknown")
    behaviors = [b.get("label") for b in (d.get("behaviors") or []) if b.get("label")]

    verdict, score = REPUTATION_VERDICTS.get(reputation, ("unknown", 0.0))

    summary = f"reputation={reputation}, confidence={confidence}"
    if behaviors:
        summary += ", behaviors: " + ", ".join(behaviors[:5])

    return SourceResult(
        name="CrowdSec CTI",
        ok=True,
        verdict=verdict,
        score=score,
        summary=summary,
        details={"reputation": reputation, "confidence": confidence, "behaviors": behaviors, "as_name": d.get("as_name"), "link": "https://app.crowdsec.net/"},
    )
