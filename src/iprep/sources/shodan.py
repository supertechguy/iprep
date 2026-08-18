from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

API_URL = "https://api.shodan.io/shodan/host/{ip}"
SETUP_HINT = (
    "Shodan requires a paid-ish API key (the $1/mo 'Freelancer' tier works) at "
    "https://account.shodan.io/register, then run `iprep keys set shodan`."
)
RISKY_TAGS = {"malware", "c2", "compromised", "honeypot", "botnet"}


def check(ip: str, ctx: Context) -> SourceResult:
    key = ctx.config.shodan_api_key
    if not key:
        return SourceResult(name="Shodan", ok=False, error="no API key configured", summary=SETUP_HINT)

    try:
        resp = ctx.session.get(API_URL.format(ip=ip), params={"key": key}, timeout=ctx.timeout)
    except requests.RequestException as e:
        return SourceResult(name="Shodan", ok=False, error=str(e), summary="request failed")

    if resp.status_code == 401:
        return SourceResult(name="Shodan", ok=False, error="invalid API key", summary=SETUP_HINT)
    if resp.status_code == 404:
        return SourceResult(name="Shodan", ok=True, verdict="unknown", score=0.0, summary="no Shodan data (not recently scanned)")
    if resp.status_code != 200:
        return SourceResult(name="Shodan", ok=False, error=f"HTTP {resp.status_code}", summary=resp.text[:200])

    d = resp.json()
    ports = sorted(d.get("ports", []) or [])
    vulns = list(d.get("vulns", []) or [])
    tags = d.get("tags", []) or []
    hit_tags = [t for t in tags if t.lower() in RISKY_TAGS]

    verdict = "suspicious" if (vulns or hit_tags) else "clean"
    score = min(100.0, len(vulns) * 15 + len(hit_tags) * 40)

    port_preview = ", ".join(map(str, ports[:8])) + ("..." if len(ports) > 8 else "")
    summary = f"{len(ports)} open ports ({port_preview}), {len(vulns)} known CVEs, tags={tags or 'none'}"
    return SourceResult(
        name="Shodan",
        ok=True,
        verdict=verdict,
        score=score,
        summary=summary,
        details={
            "ports": ports,
            "vulns": vulns,
            "tags": tags,
            "org": d.get("org"),
            "os": d.get("os"),
            "hostnames": d.get("hostnames"),
            "isp": d.get("isp"),
            "link": f"https://www.shodan.io/host/{ip}",
        },
    )
