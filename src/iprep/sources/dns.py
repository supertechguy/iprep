from __future__ import annotations

import re

import dns.resolver
import dns.reversename

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version

# Rough hostname-shape classification. Order matters - first match wins.
# These are heuristics on common ISP/hoster naming conventions, not gospel;
# they're here to answer "does this PTR look like a home connection or a
# server?" at a glance.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("CDN/edge", re.compile(r"\b(cloudflare|akamai|akamaitechnologies|fastly|edgecast|llnw|limelight|cdn77|stackpath|cachefly)\b|\bcdn\b", re.I)),
    ("mail server", re.compile(r"(^|[.-])(mail|mx\d*|smtp|mta|imap|pop3?)([.-]|$)", re.I)),
    ("cloud/hosting", re.compile(r"(amazonaws\.com|googleusercontent\.com|azure|cloudapp\.|\bovh\b|hetzner|digitalocean|linode|vultr|contabo|scaleway|leaseweb|\bm247\b|hostinger|\bvps\b|\bvhost\b)", re.I)),
    ("static/server", re.compile(r"(^|[.-])(static|static-ip|srv\d*|server\d*|dedicated|colo|rev)([.-]|$)", re.I)),
    ("dynamic/residential", re.compile(
        r"(^|[.-])(dynamic|dyn|dhcp|dsl[a-z]*|adsl|vdsl|pool|dialup|dial|ppp\d*|pppoe|cable|broadband|"
        r"client|customer|cust|cpe|res(net)?|hsd\d|fibre|fiber|wireless|mobile|gprs|lte)([.-]|$)", re.I)),
    ("dynamic/residential", re.compile(r"(^|[.-])(ip)?[-.]?\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}([.-]|$)")),
]


def _classify(hostname: str) -> str | None:
    for label, pat in _PATTERNS:
        if pat.search(hostname):
            return label
    return None


def check(ip: str, ctx: Context) -> SourceResult:
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = ctx.dns_resolver.resolve(rev_name, "PTR")
        hostname = str(answers[0]).rstrip(".")
    except dns.resolver.NXDOMAIN:
        return SourceResult(name="Reverse DNS", ok=True, verdict="unknown", category="context", summary="no PTR record")
    except Exception as e:
        return SourceResult(name="Reverse DNS", ok=False, error=str(e), category="context", summary="lookup failed")

    forward_record_type = "AAAA" if ip_version(ip) == 6 else "A"
    forward_confirmed = False
    try:
        forward = ctx.dns_resolver.resolve(hostname, forward_record_type)
        forward_confirmed = ip in {str(r) for r in forward}
    except Exception:
        pass

    tag = "forward-confirmed" if forward_confirmed else "forward mismatch/unconfirmed"
    kind = _classify(hostname)
    kind_str = f", looks like: {kind}" if kind else ""
    return SourceResult(
        name="Reverse DNS",
        ok=True,
        verdict="unknown",
        category="context",
        summary=f"PTR: {hostname} ({tag}){kind_str}",
        details={"hostname": hostname, "forward_confirmed": forward_confirmed, "connection_type": kind},
    )
