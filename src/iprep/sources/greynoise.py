from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

API_URL = "https://api.greynoise.io/v3/community/{ip}"
SETUP_HINT = (
    "Optional: free GreyNoise Community API key at https://viz.greynoise.io/signup "
    "helps distinguish mass internet scanners from targeted attackers. "
    "Run `iprep keys set greynoise`."
)


def check(ip: str, ctx: Context) -> SourceResult:
    key = ctx.config.greynoise_api_key
    if not key:
        return SourceResult(name="GreyNoise", ok=False, error="no API key configured", summary=SETUP_HINT)

    try:
        resp = ctx.session.get(API_URL.format(ip=ip), headers={"key": key}, timeout=ctx.timeout)
    except requests.RequestException as e:
        return SourceResult(name="GreyNoise", ok=False, error=str(e), summary="request failed")

    if resp.status_code == 401:
        return SourceResult(name="GreyNoise", ok=False, error="invalid API key", summary=SETUP_HINT)
    if resp.status_code == 404:
        return SourceResult(name="GreyNoise", ok=True, verdict="unknown", score=0.0, summary="no GreyNoise data (not observed scanning the internet)")
    if resp.status_code != 200:
        return SourceResult(name="GreyNoise", ok=False, error=f"HTTP {resp.status_code}", summary=resp.text[:200])

    d = resp.json()
    classification = d.get("classification", "unknown")
    noise = d.get("noise", False)
    riot = d.get("riot", False)
    name = d.get("name")

    if classification == "malicious":
        verdict, score = "malicious", 90.0
    elif classification == "benign":
        verdict, score = "clean", 0.0
    else:
        verdict, score = "unknown", 0.0

    summary = f"classification={classification}"
    if noise:
        summary += ", known internet scanner"
    if riot:
        summary += f", recognized service: {name}"

    return SourceResult(
        name="GreyNoise",
        ok=True,
        verdict=verdict,
        score=score,
        summary=summary,
        details={"classification": classification, "noise": noise, "riot": riot, "name": name, "link": d.get("link")},
    )
