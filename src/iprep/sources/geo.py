from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

# ipwho.is: free, no API key, HTTPS, IPv4 + IPv6. Returns country/region/city,
# lat/lon, timezone, and the announcing network's ASN/org/ISP. Fair-use rate
# limits only (no signup) - fine for interactive use and modest batches; a
# 429/failure just degrades this context row to "n/a" without affecting the
# verdict. Swappable: any endpoint returning country_code/region/city works.
GEO_URL = "https://ipwho.is/{ip}"


def _location(d: dict) -> str:
    return ", ".join(b for b in (d.get("city"), d.get("region"), d.get("country")) if b) or "location unknown"


def _fail(error: str, summary: str) -> SourceResult:
    return SourceResult(name="Geolocation", ok=False, error=error, summary=summary, category="context")


def check(ip: str, ctx: Context) -> SourceResult:
    try:
        resp = ctx.session.get(GEO_URL.format(ip=ip), timeout=ctx.timeout)
    except requests.RequestException as e:
        return _fail(str(e), "request failed")

    if resp.status_code != 200:
        return _fail(f"HTTP {resp.status_code}", "lookup failed")

    try:
        d = resp.json()
    except ValueError:
        return _fail("unparseable response", "lookup failed")

    if not d.get("success", False):
        # ipwho.is reports reserved/bogon space and quota exhaustion this way.
        return _fail(d.get("message") or "no geolocation data", "no geolocation data")

    country_code = (d.get("country_code") or "").upper()
    conn = d.get("connection") or {}
    home = (ctx.config.home_country or "").upper()

    is_local = None
    tag = ""
    if home and country_code:
        is_local = country_code == home
        tag = (
            f" — LOCAL (matches home country {home})"
            if is_local
            else f" — FOREIGN (home country is {home})"
        )

    return SourceResult(
        name="Geolocation",
        ok=True,
        verdict="unknown",
        category="context",
        summary=f"{_location(d)}{tag}",
        details={
            "country": d.get("country"),
            "country_code": country_code or None,
            "region": d.get("region"),
            "city": d.get("city"),
            "postal": d.get("postal"),
            "latitude": d.get("latitude"),
            "longitude": d.get("longitude"),
            "continent": d.get("continent"),
            "is_eu": d.get("is_eu"),
            "timezone": (d.get("timezone") or {}).get("id"),
            "asn": conn.get("asn"),
            "org": conn.get("org"),
            "isp": conn.get("isp"),
            "home_country": home or None,
            "is_local": is_local,
            "link": f"https://ipwho.is/{ip}",
        },
    )
