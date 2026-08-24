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


def _service_line(banner: dict) -> str:
    """One line per open port: product/version if Shodan fingerprinted it,
    falling back to the HTTP title, falling back to just the bare port."""
    port = banner.get("port")
    transport = banner.get("transport", "tcp")
    label = banner.get("product") or ""
    if banner.get("version"):
        label = f"{label} {banner['version']}".strip()
    http = banner.get("http") or {}
    if http.get("title"):
        label = f'{label} — "{http["title"]}"'.strip(" —")
    return f"{port}/{transport}: {label or '?'}"


def _cert_note(banner: dict) -> str | None:
    ssl = banner.get("ssl") or {}
    cert = ssl.get("cert") or {}
    if not cert:
        return None
    subject = (cert.get("subject") or {}).get("CN")
    issuer = (cert.get("issuer") or {}).get("CN")
    bits = []
    if subject:
        bits.append(f"CN={subject}")
    if issuer and issuer != subject:
        bits.append(f"issuer={issuer}")
    if cert.get("expired"):
        bits.append("EXPIRED")
    if not bits:
        return None
    return f"port {banner.get('port')}: " + ", ".join(bits)


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
    vulns = sorted(d.get("vulns", []) or [])
    tags = d.get("tags", []) or []
    hit_tags = [t for t in tags if t.lower() in RISKY_TAGS]
    banners = sorted(d.get("data", []) or [], key=lambda b: b.get("port", 0))

    # Per-service fingerprints (product/version/HTTP title) live on the
    # individual port banners, not the top-level fields - this is Shodan's
    # actual headline value beyond a bare port list.
    services = [_service_line(b) for b in banners]
    certs = [c for c in (_cert_note(b) for b in banners) if c]

    # Likewise, CVSS score and "did Shodan verify this, or just CPE-match
    # it" live per-banner, not in the top-level vulns list, which is just
    # bare CVE IDs.
    vuln_detail: dict[str, dict] = {}
    for b in banners:
        banner_vulns = b.get("vulns")
        if not isinstance(banner_vulns, dict):
            continue
        for cve_id, info in banner_vulns.items():
            if cve_id not in vuln_detail:
                vuln_detail[cve_id] = {
                    "cvss": info.get("cvss"),
                    "verified": bool(info.get("verified")),
                    "summary": (info.get("summary") or "")[:200],
                }
    high_severity = [c for c, v in vuln_detail.items() if (v.get("cvss") or 0) >= 7.0]

    verdict = "suspicious" if (vulns or hit_tags) else "clean"
    score = min(100.0, len(vulns) * 15 + len(hit_tags) * 40)

    port_preview = ", ".join(map(str, ports[:8])) + ("..." if len(ports) > 8 else "")
    summary_parts = [f"{len(ports)} open ports ({port_preview})" if ports else "no open ports on record"]
    if vulns:
        cve_note = f"{len(vulns)} known CVEs"
        if high_severity:
            cve_note += f" ({len(high_severity)} CVSS ≥ 7.0)"
        summary_parts.append(cve_note)
    if hit_tags:
        summary_parts.append("risky tags: " + ", ".join(hit_tags))
    elif tags:
        summary_parts.append("tags: " + ", ".join(tags))
    summary = ", ".join(summary_parts)

    return SourceResult(
        name="Shodan",
        ok=True,
        verdict=verdict,
        score=score,
        summary=summary,
        details={
            "ports": ports,
            "services": services,
            "vulns": vulns,
            "vuln_detail": vuln_detail,
            "certs": certs,
            "tags": tags,
            "org": d.get("org"),
            "isp": d.get("isp"),
            "asn": d.get("asn"),
            "os": d.get("os"),
            "hostnames": d.get("hostnames"),
            "domains": d.get("domains"),
            "city": d.get("city"),
            "country": d.get("country_name"),
            "last_update": d.get("last_update"),
            "link": f"https://www.shodan.io/host/{ip}",
        },
    )
