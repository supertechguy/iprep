from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

# abuse.ch ThreatFox - curated malware IOC feed with malware-family and
# confidence-level tagging. The query API requires a free Auth-Key (instant
# signup via GitHub/Google/etc, no approval wait) - confirmed mandatory,
# unlike Feodo Tracker/BinaryDefense's plain downloadable lists.
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
SETUP_HINT = "Free instant signup at https://auth.abuse.ch/ then run `iprep keys set threatfox`."


def check(ip: str, ctx: Context) -> SourceResult:
    key = ctx.config.threatfox_api_key
    if not key:
        return SourceResult(name="ThreatFox", ok=False, error="no API key configured", summary=SETUP_HINT)

    try:
        resp = ctx.session.post(
            API_URL,
            json={"query": "search_ioc", "search_term": ip, "exact_match": True},
            headers={"Auth-Key": key},
            timeout=ctx.timeout,
        )
    except requests.RequestException as e:
        return SourceResult(name="ThreatFox", ok=False, error=str(e), summary="request failed")

    if resp.status_code == 401:
        return SourceResult(name="ThreatFox", ok=False, error="invalid API key", summary=SETUP_HINT)
    if resp.status_code != 200:
        return SourceResult(name="ThreatFox", ok=False, error=f"HTTP {resp.status_code}", summary=resp.text[:200])

    body = resp.json()
    status = body.get("query_status")
    link = "https://threatfox.abuse.ch/"

    if status == "no_result":
        return SourceResult(name="ThreatFox", ok=True, verdict="clean", score=0.0, summary="no ThreatFox IOCs for this IP", details={"link": link})
    if status != "ok":
        return SourceResult(name="ThreatFox", ok=False, error=f"query_status={status}", summary="unexpected response")

    entries = body.get("data") or []
    if not entries:
        return SourceResult(name="ThreatFox", ok=True, verdict="clean", score=0.0, summary="no ThreatFox IOCs for this IP", details={"link": link})

    top = max(entries, key=lambda e: e.get("confidence_level", 0) or 0)
    confidence = top.get("confidence_level", 0) or 0
    malware = top.get("malware_printable") or top.get("malware")
    threat_type = top.get("threat_type_desc") or top.get("threat_type")

    verdict = "malicious" if confidence >= 50 else "suspicious"
    summary = f"{threat_type or 'IOC'}: {malware or 'unknown malware'} (confidence {confidence})"
    return SourceResult(
        name="ThreatFox",
        ok=True,
        verdict=verdict,
        score=float(confidence),
        summary=summary,
        details={"entries": len(entries), "malware": malware, "threat_type": threat_type, "confidence": confidence, "link": link},
    )
