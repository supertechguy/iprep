from __future__ import annotations

import dns.resolver

from ..base import SourceResult
from ..context import Context

# https://www.spamhaus.org/blocklists/zen-blocklist/  - return codes decoded here
ZEN_CODES = {
    "127.0.0.2": "SBL: spammer / spam source",
    "127.0.0.3": "SBL CSS: snowshoe spam",
    "127.0.0.4": "XBL: infected/compromised host (exploited)",
    "127.0.0.9": "SBL DROP/EDROP: hijacked/stolen netblock, do not route",
    "127.0.0.10": "PBL: dynamic/residential IP, should not send mail directly",
    "127.0.0.11": "PBL: ISP-maintained dynamic IP policy block",
}
# The PBL is a *policy* list (huge swaths of ordinary residential/dynamic IPs
# are listed there by their ISPs) - it is not an abuse signal on its own.
# Only SBL/XBL/CSS/DROP codes indicate actual observed malicious behavior.
PBL_CODES = {"127.0.0.10", "127.0.0.11"}
SETUP_HINT = (
    "Free public DNSBL lookups are used by default (fine for personal, low-volume use). "
    "For heavier/production use, get a Spamhaus DQS key (https://www.spamhaus.com/product/data-query-service/) "
    "and set SPAMHAUS_DQS_KEY for a more reliable, higher-volume endpoint."
)


def check(ip: str, ctx: Context) -> SourceResult:
    octets = ip.split(".")
    if len(octets) != 4:
        return SourceResult(name="Spamhaus", ok=False, error="IPv6 not supported by this check", summary="skipped")

    dqs_key = ctx.config.spamhaus_dqs_key
    zone = f"{dqs_key}.zen.dq.spamhaus.net" if dqs_key else "zen.spamhaus.org"
    query = ".".join(reversed(octets)) + "." + zone

    try:
        answers = ctx.dns_resolver.resolve(query, "A")
        codes = [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        return SourceResult(
            name="Spamhaus", ok=True, verdict="clean", score=0.0,
            summary="not listed on Spamhaus ZEN", details={"link": "https://check.spamhaus.org/"},
        )
    except dns.resolver.NoNameservers:
        return SourceResult(
            name="Spamhaus", ok=False, error="query blocked/rate-limited",
            summary="public Spamhaus mirror may be blocking your resolver; " + SETUP_HINT,
        )
    except Exception as e:
        return SourceResult(name="Spamhaus", ok=False, error=str(e), summary="lookup failed")

    reasons = [ZEN_CODES.get(c, f"{c}: listed") for c in codes]
    abuse_codes = [c for c in codes if c not in PBL_CODES]

    if abuse_codes:
        verdict, score = "malicious", 100.0
    else:
        # PBL-only: expected for lots of ordinary residential/dynamic IPs,
        # only worth flagging as a soft signal.
        verdict, score = "suspicious", 20.0

    return SourceResult(
        name="Spamhaus",
        ok=True,
        verdict=verdict,
        score=score,
        summary="listed on Spamhaus ZEN: " + "; ".join(reasons),
        details={"return_codes": codes, "link": "https://check.spamhaus.org/"},
    )
