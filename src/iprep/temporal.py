"""Recency of the evidence behind a verdict.

Every source is a point-in-time snapshot; a few of them also say *when* they
last saw the IP misbehave. Surfacing that stops "flagged three years ago, quiet
since" from reading the same as "flagged yesterday" - and lets the aggregate
decline to slam the verdict to malicious on the strength of a single stale hit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from .base import SourceResult

# Reputation sources that expose a "last observed" timestamp in their details,
# and which detail key(s) hold it (most recent wins).
LAST_SEEN_KEYS: dict[str, tuple[str, ...]] = {
    "AbuseIPDB": ("last_reported",),
    "ThreatFox": ("last_seen",),
    "GreyNoise": ("last_seen",),
    "CrowdSec CTI": ("last_seen",),
}

STALE_AFTER_DAYS = 365


def _parse_date(value) -> date | None:
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00").replace(" UTC", "")
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[: len("2020-01-01 00:00:00")], fmt).date()
        except ValueError:
            continue
    return None


@dataclass
class Temporal:
    last_flagged: date | None = None          # newest "last seen bad" across sources
    age_days: int | None = None               # how long ago that was
    stale: bool = False                       # older than STALE_AFTER_DAYS
    per_source: dict[str, str] = field(default_factory=dict)  # name -> ISO date
    # names of malicious/suspicious sources that expose *no* date at all
    undated_flaggers: list[str] = field(default_factory=list)

    @property
    def all_flaggers_dated(self) -> bool:
        return bool(self.per_source) and not self.undated_flaggers

    def describe(self) -> str | None:
        if not self.last_flagged:
            return None
        yrs = (self.age_days or 0) / 365.25
        ago = f"{self.age_days}d ago" if (self.age_days or 0) < 365 else f"{yrs:.1f}y ago"
        note = "  ⚠ stale" if self.stale else ""
        return f"most recent flagged activity: {self.last_flagged.isoformat()} ({ago}){note}"


def summarize(results: list[SourceResult]) -> Temporal:
    per_source: dict[str, date] = {}
    undated: list[str] = []

    for r in results:
        if not r.ok or r.category != "reputation" or r.verdict not in ("malicious", "suspicious"):
            continue
        keys = LAST_SEEN_KEYS.get(r.name)
        found: date | None = None
        if keys:
            for k in keys:
                d = _parse_date((r.details or {}).get(k))
                if d and (found is None or d > found):
                    found = d
        if found:
            per_source[r.name] = found
        else:
            undated.append(r.name)

    if not per_source:
        return Temporal(undated_flaggers=sorted(undated))

    latest = max(per_source.values())
    age = (datetime.now(timezone.utc).date() - latest).days
    return Temporal(
        last_flagged=latest,
        age_days=age,
        stale=age > STALE_AFTER_DAYS,
        per_source={name: d.isoformat() for name, d in sorted(per_source.items())},
        undated_flaggers=sorted(undated),
    )
