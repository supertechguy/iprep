from __future__ import annotations

import csv
import io
import ipaddress
import json

from ..base import SourceResult
from ..context import Context
from ..netutil import cached_origin

# "Is this a cloud VM, and whose / which region?" - more actionable than the
# VPN/Proxy source's binary "datacenter or not". Providers that publish an
# authoritative machine-readable range list get exact prefix + region matching;
# the rest fall back to origin-ASN attribution. Context only: running in AWS
# isn't suspicious.
CIDR_TTL = 24 * 3600

# name -> (cache filename, url, parser key). Parsers below yield (region, cidr).
_AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
_GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
_OCI_URL = "https://docs.oracle.com/iaas/tools/public_ip_ranges.json"
_DO_URL = "https://www.digitalocean.com/geo/google.csv"
_CF4_URL = "https://www.cloudflare.com/ips-v4"
_CF6_URL = "https://www.cloudflare.com/ips-v6"

# Origin-ASN fallback for providers without a usable published range file
# (or when a prefix-list fetch fails). Not exhaustive - the big hosters people
# actually see in logs.
_ASN_PROVIDERS = {
    "8075": "Microsoft Azure", "8068": "Microsoft Azure", "8069": "Microsoft Azure",
    "16509": "Amazon AWS", "14618": "Amazon AWS", "38895": "Amazon AWS",
    "15169": "Google", "396982": "Google Cloud", "19527": "Google Cloud",
    "13335": "Cloudflare",
    "14061": "DigitalOcean",
    "24940": "Hetzner", "213230": "Hetzner",
    "16276": "OVHcloud",
    "20473": "Vultr / Constant", "64515": "Vultr",
    "63949": "Akamai / Linode", "48163": "Linode", "3595": "Linode",
    "51167": "Contabo",
    "60781": "Leaseweb", "28753": "Leaseweb", "30633": "Leaseweb", "19148": "Leaseweb",
    "9009": "M247",
    "12876": "Scaleway",
    "14178": "Alibaba Cloud", "45102": "Alibaba Cloud", "37963": "Alibaba Cloud",
    "132203": "Tencent Cloud",
    "20454": "Netcup",
}


def _nets(text_lines: list[str]) -> list:
    out = []
    for line in text_lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return out


def _aws(text: str, addr) -> str | None:
    d = json.loads(text)
    key = "ipv6_prefixes" if addr.version == 6 else "prefixes"
    pfx_key = "ipv6_prefix" if addr.version == 6 else "ip_prefix"
    for row in d.get(key, []):
        try:
            if addr in ipaddress.ip_network(row[pfx_key]):
                return row.get("region") or "?"
        except (ValueError, KeyError):
            continue
    return None


def _gcp(text: str, addr) -> str | None:
    d = json.loads(text)
    pfx_key = "ipv6Prefix" if addr.version == 6 else "ipv4Prefix"
    for row in d.get("prefixes", []):
        cidr = row.get(pfx_key)
        if not cidr:
            continue
        try:
            if addr in ipaddress.ip_network(cidr):
                return row.get("scope") or "?"
        except ValueError:
            continue
    return None


def _oci(text: str, addr) -> str | None:
    d = json.loads(text)
    for region in d.get("regions", []):
        for entry in region.get("cidrs", []):
            try:
                if addr in ipaddress.ip_network(entry["cidr"]):
                    return region.get("region") or "?"
            except (ValueError, KeyError):
                continue
    return None


def _do(text: str, addr) -> str | None:
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        try:
            if addr in ipaddress.ip_network(row[0]):
                loc = ", ".join(p for p in row[1:4] if p)
                return loc or "?"
        except ValueError:
            continue
    return None


def _cf(text: str, addr) -> str | None:
    return "anycast (global)" if any(addr in n for n in _nets(text.splitlines())) else None


_FEEDS = [
    ("Amazon AWS", "aws_ip_ranges.json", _AWS_URL, _aws, (4, 6)),
    ("Google Cloud", "gcp_cloud.json", _GCP_URL, _gcp, (4, 6)),
    ("Oracle OCI", "oci_ip_ranges.json", _OCI_URL, _oci, (4,)),
    ("DigitalOcean", "digitalocean.csv", _DO_URL, _do, (4, 6)),
    ("Cloudflare", "cloudflare_v4.txt", _CF4_URL, _cf, (4,)),
    ("Cloudflare", "cloudflare_v6.txt", _CF6_URL, _cf, (6,)),
]


def check(ip: str, ctx: Context) -> SourceResult:
    addr = ipaddress.ip_address(ip)
    errors: list[str] = []

    for provider, cache_name, url, parser, versions in _FEEDS:
        if addr.version not in versions:
            continue
        try:
            text = ctx.cache.get_text(cache_name, url, CIDR_TTL, ctx.session)
        except Exception as e:
            errors.append(f"{provider}: {e}")
            continue
        try:
            region = parser(text, addr)
        except Exception as e:
            errors.append(f"{provider} parse: {e}")
            continue
        if region:
            loc = f" ({region})" if region and region != "?" else ""
            return SourceResult(
                name="Cloud", ok=True, verdict="unknown", category="context",
                summary=f"{provider}{loc}",
                details={"provider": provider, "region": region, "method": "published prefix list", "errors": errors},
            )

    # Fall back to origin-ASN attribution.
    origin = cached_origin(ip, ctx)
    if origin and origin["asn"] in _ASN_PROVIDERS:
        provider = _ASN_PROVIDERS[origin["asn"]]
        return SourceResult(
            name="Cloud", ok=True, verdict="unknown", category="context",
            summary=f"{provider} (via AS{origin['asn']}; no prefix-level region data)",
            details={"provider": provider, "region": None, "method": "origin ASN", "asn": origin["asn"], "errors": errors},
        )

    if errors and len(errors) >= sum(1 for _, _, _, _, v in _FEEDS if addr.version in v):
        return SourceResult(name="Cloud", ok=False, error="; ".join(errors), summary="could not fetch any cloud provider range list", category="context")

    return SourceResult(
        name="Cloud", ok=True, verdict="unknown", category="context",
        summary="not in a known cloud provider's published range",
        details={"provider": None, "errors": errors},
    )
