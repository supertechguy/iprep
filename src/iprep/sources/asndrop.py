from __future__ import annotations

import json

from ..base import SourceResult
from ..context import Context
from ..netutil import cached_origin

# Spamhaus ASN-DROP: whole autonomous systems that are hijacked or operated by
# bad actors ("bulletproof" hosting). Membership means the entire network the
# IP lives in is disreputable - a strong signal even if the specific IP hasn't
# been reported yet - so this is a reputation source, not just context.
ASNDROP_URL = "https://www.spamhaus.org/drop/asndrop.json"
ASNDROP_TTL = 24 * 3600


def _asndrop(ctx: Context) -> dict[int, dict]:
    text = ctx.cache.get_text("spamhaus_asndrop.json", ASNDROP_URL, ASNDROP_TTL, ctx.session)
    out: dict[int, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("asn"), int):
            out[obj["asn"]] = obj
    return out


def check(ip: str, ctx: Context) -> SourceResult:
    origin = cached_origin(ip, ctx)
    if origin is None or not origin["asn"]:
        return SourceResult(name="Spamhaus ASN-DROP", ok=True, verdict="unknown", summary="no announced origin AS to check")

    try:
        asn = int(origin["asn"])
    except ValueError:
        return SourceResult(name="Spamhaus ASN-DROP", ok=True, verdict="unknown", summary="unparseable origin AS")

    try:
        listed = _asndrop(ctx)
    except Exception as e:
        return SourceResult(name="Spamhaus ASN-DROP", ok=False, error=str(e), summary="could not fetch ASN-DROP list")

    if asn in listed:
        entry = listed[asn]
        who = entry.get("asname") or entry.get("domain") or "?"
        return SourceResult(
            name="Spamhaus ASN-DROP",
            ok=True,
            verdict="malicious",
            score=75.0,
            summary=f"AS{asn} ({who}) is on Spamhaus ASN-DROP — hijacked or bulletproof-hosting AS",
            details={"asn": asn, "asname": entry.get("asname"), "domain": entry.get("domain"), "rir": entry.get("rir"), "link": "https://www.spamhaus.org/drop/"},
        )

    return SourceResult(
        name="Spamhaus ASN-DROP",
        ok=True,
        verdict="clean",
        score=0.0,
        summary=f"AS{asn} not on Spamhaus ASN-DROP ({len(listed)} ASes listed)",
        details={"asn": asn},
    )
