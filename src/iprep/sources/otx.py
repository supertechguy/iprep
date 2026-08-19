from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version

# AlienVault OTX (rebranded "LevelBlue OTX" in docs, but otx.alienvault.com
# is still the live domain). Works fully unauthenticated for basic IP
# lookups (verified live) - an optional free key just raises your rate
# limit. Rather than a blunt malicious/clean flag, OTX tells you how many
# threat-intel "pulses" (curated IOC collections other analysts published)
# reference this IP, and what they're called - real context, though pulse
# quality varies since anyone can publish one.
API_URL = "https://otx.alienvault.com/api/v1/indicators/{family}/{ip}/general"
SETUP_HINT = "Works without a key. Optional free key at https://otx.alienvault.com/ raises your rate limit; run `iprep keys set otx`."


def check(ip: str, ctx: Context) -> SourceResult:
    family = "IPv6" if ip_version(ip) == 6 else "IPv4"
    headers = {}
    key = ctx.config.otx_api_key
    if key:
        headers["X-OTX-API-Key"] = key

    try:
        resp = ctx.session.get(API_URL.format(family=family, ip=ip), headers=headers, timeout=ctx.timeout)
    except requests.RequestException as e:
        return SourceResult(name="AlienVault OTX", ok=False, error=str(e), summary="request failed")

    if resp.status_code == 429:
        return SourceResult(name="AlienVault OTX", ok=False, error="rate limited", summary=SETUP_HINT)
    if resp.status_code != 200:
        return SourceResult(name="AlienVault OTX", ok=False, error=f"HTTP {resp.status_code}", summary=resp.text[:200])

    data = resp.json()
    pulse_info = data.get("pulse_info", {}) or {}
    count = pulse_info.get("count", 0) or 0
    pulses = pulse_info.get("pulses", []) or []
    pulse_names = [p.get("name") for p in pulses[:5] if p.get("name")]
    link = f"https://otx.alienvault.com/indicator/ip/{ip}"

    if count == 0:
        return SourceResult(
            name="AlienVault OTX", ok=True, verdict="clean", score=0.0,
            summary="not referenced in any OTX threat-intel pulses",
            details={"link": link},
        )

    score = min(100.0, count * 10.0)
    verdict = "malicious" if count >= 5 else "suspicious"
    summary = f"referenced in {count} OTX pulse(s): " + ", ".join(pulse_names) + ("..." if len(pulses) > 5 else "")
    return SourceResult(
        name="AlienVault OTX",
        ok=True,
        verdict=verdict,
        score=score,
        summary=summary,
        details={"pulse_count": count, "pulse_names": pulse_names, "reputation": data.get("reputation"), "link": link},
    )
