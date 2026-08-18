from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

API_URL = "https://api.abuseipdb.com/api/v2/check"
SETUP_HINT = (
    "Get a free AbuseIPDB API key at https://www.abuseipdb.com/register "
    "(1000 checks/day), then run `iprep keys set abuseipdb`."
)


def check(ip: str, ctx: Context) -> SourceResult:
    key = ctx.config.abuseipdb_api_key
    if not key:
        return SourceResult(name="AbuseIPDB", ok=False, error="no API key configured", summary=SETUP_HINT)

    try:
        resp = ctx.session.get(
            API_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=ctx.timeout,
        )
    except requests.RequestException as e:
        return SourceResult(name="AbuseIPDB", ok=False, error=str(e), summary="request failed")

    if resp.status_code == 401:
        return SourceResult(name="AbuseIPDB", ok=False, error="invalid API key", summary=SETUP_HINT)
    if resp.status_code == 429:
        return SourceResult(name="AbuseIPDB", ok=False, error="rate limited", summary="daily quota hit")
    if resp.status_code != 200:
        return SourceResult(name="AbuseIPDB", ok=False, error=f"HTTP {resp.status_code}", summary=resp.text[:200])

    d = resp.json().get("data", {})
    score = float(d.get("abuseConfidenceScore", 0))
    reports = d.get("totalReports", 0)

    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"

    summary = f"abuse confidence {score:.0f}%, {reports} reports, {d.get('isp', '?')} ({d.get('countryCode', '?')})"
    return SourceResult(
        name="AbuseIPDB",
        ok=True,
        verdict=verdict,
        score=score,
        summary=summary,
        details={
            "total_reports": reports,
            "distinct_users": d.get("numDistinctUsers"),
            "last_reported": d.get("lastReportedAt"),
            "is_tor": d.get("isTor"),
            "usage_type": d.get("usageType"),
            "domain": d.get("domain"),
            "isp": d.get("isp"),
            "country": d.get("countryCode"),
            "link": f"https://www.abuseipdb.com/check/{ip}",
        },
    )
