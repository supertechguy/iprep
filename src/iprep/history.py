"""Optional local journal of every check, so you can build your own
first-seen / last-seen picture over time (off by default; turn it on with
`iprep config set journal on`).

Best-effort throughout: a journal problem must never break or slow a check,
so every DB error is swallowed.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(os.environ.get("IPREP_DATA_DIR", Path.home() / ".local" / "share" / "iprep"))
DB_PATH = DATA_DIR / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    ts            TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    score         REAL,
    sources_ok    INTEGER,
    sources_total INTEGER,
    flagged_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_ip ON checks(ip);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);
"""


def enabled(config) -> bool:
    return str(getattr(config, "journal", "") or "").strip().lower() in ("on", "1", "true", "yes", "enabled")


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def record(ip: str, verdict) -> None:
    try:
        with closing(_connect()) as conn, conn:
            conn.execute(
                "INSERT INTO checks(ip, ts, verdict, score, sources_ok, sources_total, flagged_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    ip,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    verdict.label,
                    verdict.score,
                    verdict.sources_ok,
                    verdict.sources_total,
                    ";".join(verdict.contributing),
                ),
            )
    except sqlite3.Error:
        pass


def prior_checks(ip: str) -> list[sqlite3.Row]:
    try:
        with closing(_connect()) as conn:
            return conn.execute("SELECT * FROM checks WHERE ip = ? ORDER BY ts", (ip,)).fetchall()
    except sqlite3.Error:
        return []


def recent(limit: int = 25) -> list[sqlite3.Row]:
    try:
        with closing(_connect()) as conn:
            return conn.execute("SELECT * FROM checks ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    except sqlite3.Error:
        return []


@dataclass
class PriorSummary:
    count: int
    first_ts: str
    last_ts: str
    last_verdict: str
    changed: bool  # did the verdict differ across history?

    def describe(self) -> str:
        base = f"local journal: {self.count} prior check(s) since {self.first_ts[:10]}, last was '{self.last_verdict}' on {self.last_ts[:10]}"
        return base + ("  ⚠ verdict has changed over time" if self.changed else "")


def prior_summary(ip: str) -> PriorSummary | None:
    rows = prior_checks(ip)
    if not rows:
        return None
    verdicts = {r["verdict"] for r in rows}
    return PriorSummary(
        count=len(rows),
        first_ts=rows[0]["ts"],
        last_ts=rows[-1]["ts"],
        last_verdict=rows[-1]["verdict"],
        changed=len(verdicts) > 1,
    )
