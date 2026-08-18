from __future__ import annotations

from dataclasses import dataclass

from .base import SourceResult

# Relative confidence weighting for the sources that contribute to the score.
# Direct blocklist/DNSBL hits (Spamhaus, Talos) and the two big multi-engine
# reputation APIs are weighted highest; Shodan and GreyNoise are softer,
# context-flavored signals so they count for less.
WEIGHTS = {
    "VirusTotal": 1.0,
    "AbuseIPDB": 1.0,
    "Spamhaus": 1.0,
    "Talos": 1.0,
    "FireHOL": 0.8,
    "GreyNoise": 0.7,
    "Shodan": 0.5,
}


@dataclass
class Verdict:
    label: str  # malicious | suspicious | clean | unknown
    score: float  # 0-100 weighted average
    contributing: list[str]
    sources_ok: int
    sources_total: int


def aggregate(results: list[SourceResult]) -> Verdict:
    rep = [r for r in results if r.category == "reputation"]
    usable = [r for r in rep if r.ok and r.score is not None]

    if not usable:
        return Verdict(label="unknown", score=0.0, contributing=[], sources_ok=0, sources_total=len(rep))

    weight_total = sum(WEIGHTS.get(r.name, 1.0) for r in usable)
    weighted_sum = sum(r.score * WEIGHTS.get(r.name, 1.0) for r in usable)
    score = weighted_sum / weight_total if weight_total else 0.0

    contributing = [r.name for r in usable if r.verdict in ("malicious", "suspicious")]

    # A single high-confidence blocklist/API hit is enough to call it malicious
    # outright, even if the weighted average gets diluted by quiet sources.
    hard_hits = [r for r in usable if r.verdict == "malicious" and WEIGHTS.get(r.name, 1.0) >= 1.0]

    if hard_hits or score >= 50:
        label = "malicious"
    elif score >= 15 or any(r.verdict == "suspicious" for r in usable):
        label = "suspicious"
    else:
        label = "clean"

    return Verdict(
        label=label,
        score=round(score, 1),
        contributing=contributing,
        sources_ok=len(usable),
        sources_total=len(rep),
    )
