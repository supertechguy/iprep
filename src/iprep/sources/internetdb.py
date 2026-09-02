from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

# Shodan's InternetDB: the free, no-key, no-signup slice of Shodan's scan data.
# https://internetdb.shodan.io/<ip> -> {ports, cpes, hostnames, tags, vulns}.
# Much thinner than the paid Shodan API (no banners, no timestamps, no per-CVE
# CVSS) but it's the only open port/vuln view most users will have, so it's
# worth surfacing. Stays a context source: an open port isn't malice.
API_URL = "https://internetdb.shodan.io/{ip}"


def check(ip: str, ctx: Context) -> SourceResult:
    try:
        resp = ctx.session.get(API_URL.format(ip=ip), timeout=ctx.timeout)
    except requests.RequestException as e:
        return SourceResult(name="InternetDB", ok=False, error=str(e), summary="request failed", category="context")

    if resp.status_code == 404:
        return SourceResult(name="InternetDB", ok=True, verdict="unknown", category="context", summary="no scan data (no observed open ports)")
    if resp.status_code == 429:
        return SourceResult(name="InternetDB", ok=False, error="rate limited", summary="try again shortly", category="context")
    if resp.status_code != 200:
        return SourceResult(name="InternetDB", ok=False, error=f"HTTP {resp.status_code}", summary="lookup failed", category="context")

    try:
        d = resp.json()
    except ValueError:
        return SourceResult(name="InternetDB", ok=False, error="unparseable response", summary="lookup failed", category="context")

    ports = sorted(d.get("ports") or [])
    vulns = sorted(d.get("vulns") or [])
    tags = d.get("tags") or []
    hostnames = d.get("hostnames") or []

    bits = []
    if ports:
        shown = ", ".join(str(p) for p in ports[:12]) + (" …" if len(ports) > 12 else "")
        bits.append(f"{len(ports)} open port(s): {shown}")
    else:
        bits.append("no open ports observed")
    if vulns:
        bits.append(f"{len(vulns)} known CVE(s): " + ", ".join(vulns[:6]) + (" …" if len(vulns) > 6 else ""))
    if tags:
        bits.append("tags: " + ", ".join(tags))

    return SourceResult(
        name="InternetDB",
        ok=True,
        verdict="unknown",
        category="context",
        summary="; ".join(bits),
        details={
            "ports": ports,
            "vulns": vulns,
            "tags": tags,
            "cpes": d.get("cpes") or [],
            "hostnames": hostnames,
            "link": f"https://internetdb.shodan.io/{ip}",
        },
    )
