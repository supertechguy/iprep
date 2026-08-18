from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
SETUP_HINT = (
    "Get a free VirusTotal API key at https://www.virustotal.com/gui/join-us "
    "(4 req/min, 500/day), then run `iprep keys set virustotal`."
)


def check(ip: str, ctx: Context) -> SourceResult:
    key = ctx.config.vt_api_key
    if not key:
        return SourceResult(name="VirusTotal", ok=False, error="no API key configured", summary=SETUP_HINT)

    try:
        resp = ctx.session.get(API_URL.format(ip=ip), headers={"x-apikey": key}, timeout=ctx.timeout)
    except requests.RequestException as e:
        return SourceResult(name="VirusTotal", ok=False, error=str(e), summary="request failed")

    if resp.status_code == 401:
        return SourceResult(name="VirusTotal", ok=False, error="invalid API key", summary=SETUP_HINT)
    if resp.status_code == 429:
        return SourceResult(name="VirusTotal", ok=False, error="rate limited", summary="VT rate limit hit, try again later")
    if resp.status_code == 404:
        return SourceResult(name="VirusTotal", ok=True, verdict="unknown", score=0.0, summary="no data on file for this IP")
    if resp.status_code != 200:
        return SourceResult(name="VirusTotal", ok=False, error=f"HTTP {resp.status_code}", summary=resp.text[:200])

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    reputation = data.get("reputation", 0)
    tags = data.get("tags", [])

    score = min(100.0, (malicious * 100 + suspicious * 40) / total)
    if malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"

    summary = f"{malicious}/{total} engines flag malicious, {suspicious} suspicious, reputation={reputation}"
    return SourceResult(
        name="VirusTotal",
        ok=True,
        verdict=verdict,
        score=round(score, 1),
        summary=summary,
        details={
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": reputation,
            "tags": tags,
            "as_owner": data.get("as_owner"),
            "country": data.get("country"),
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}",
        },
    )
