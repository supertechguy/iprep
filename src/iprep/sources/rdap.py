from __future__ import annotations

import requests

from ..base import SourceResult
from ..context import Context

# rdap.org is the IETF/NRO-maintained bootstrap redirector: it 302s to
# whichever RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC) actually holds the record,
# so one endpoint covers all of them with structured JSON (RFC 9083) instead
# of scraping legacy whois text.
RDAP_URL = "https://rdap.org/ip/{ip}"


def _extract_org_and_abuse(entities: list[dict]) -> tuple[str | None, str | None]:
    org = None
    abuse_email = None
    for entity in entities:
        vcard = entity.get("vcardArray")
        if vcard and len(vcard) > 1 and org is None:
            for field in vcard[1]:
                if field[0] == "fn":
                    org = field[3]
        if "abuse" in (entity.get("roles") or []):
            for sub in entity.get("entities") or [entity]:
                sub_vcard = sub.get("vcardArray")
                if sub_vcard and len(sub_vcard) > 1:
                    for field in sub_vcard[1]:
                        if field[0] == "email":
                            abuse_email = field[3]
    return org, abuse_email


def check(ip: str, ctx: Context) -> SourceResult:
    try:
        resp = ctx.session.get(RDAP_URL.format(ip=ip), timeout=ctx.timeout, headers={"Accept": "application/rdap+json"})
    except requests.RequestException as e:
        return SourceResult(name="RDAP/Whois", ok=False, error=str(e), summary="request failed", category="context")

    if resp.status_code != 200:
        return SourceResult(name="RDAP/Whois", ok=False, error=f"HTTP {resp.status_code}", summary="no RDAP record found", category="context")

    d = resp.json()
    name = d.get("name")
    country = d.get("country")
    start = d.get("startAddress")
    end = d.get("endAddress")
    org, abuse_email = _extract_org_and_abuse(d.get("entities", []) or [])

    summary = f"{org or name or 'unknown org'} ({country or '??'}), range {start}-{end}"
    return SourceResult(
        name="RDAP/Whois",
        ok=True,
        verdict="unknown",
        category="context",
        summary=summary,
        details={
            "network_name": name,
            "handle": d.get("handle"),
            "org": org,
            "country": country,
            "range": f"{start} - {end}",
            "abuse_email": abuse_email,
            "link": f"https://rdap.org/ip/{ip}",
        },
    )
