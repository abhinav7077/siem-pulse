# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
state_store.py
==============
SQLite history of every run, so SIEM Pulse can tell what changed.

config.yaml:

    state:
      path: siem_pulse.db       # ":memory:" keeps nothing between runs
      keep_days: 90             # older run results are pruned

Tables:
    runs          one row per check cycle (counts, scope, duration)
    results       one row per device per run
    device_state  current status of each device, since when, alert bookkeeping
                  and ticket references (PagerDuty / Opsgenie / ServiceNow / Jira)
    snoozes       manual snoozes (--snooze)
    metrics       per-device volume samples for baselines (Phase 4)
    meta          small key/value facts (e.g. when the last digest was sent)
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    scope TEXT,
    total INTEGER DEFAULT 0,
    healthy INTEGER DEFAULT 0,
    stale INTEGER DEFAULT 0,
    error INTEGER DEFAULT 0,
    suppressed INTEGER DEFAULT 0,
    duration_seconds REAL
);
CREATE TABLE IF NOT EXISTS results (
    run_id INTEGER NOT NULL,
    device_key TEXT NOT NULL,
    device_name TEXT,
    ip_address TEXT,
    client_name TEXT,
    siem_platform TEXT,
    criticality TEXT,
    status TEXT,
    suppressed TEXT,
    last_log_time TEXT,
    hours_since_last_log REAL,
    error TEXT,
    checked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_device ON results(device_key);
CREATE TABLE IF NOT EXISTS device_state (
    device_key TEXT PRIMARY KEY,
    device_name TEXT,
    ip_address TEXT,
    client_name TEXT,
    siem_platform TEXT,
    criticality TEXT,
    status TEXT,
    since TEXT,
    last_checked_at TEXT,
    last_log_time TEXT,
    error TEXT,
    suppressed TEXT,
    alerted INTEGER DEFAULT 0,
    last_alert_at TEXT,
    alert_count INTEGER DEFAULT 0,
    tickets TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS snoozes (
    device_key TEXT PRIMARY KEY,
    device_name TEXT,
    until TEXT NOT NULL,
    reason TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS metrics (
    device_key TEXT NOT NULL,
    ts TEXT NOT NULL,
    events_per_hour REAL,
    unparsed_ratio REAL,
    max_skew_seconds REAL,
    log_types TEXT
);
CREATE INDEX IF NOT EXISTS idx_metrics_device ON metrics(device_key, ts);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

ISSUE_STATUSES = ("stale", "error")


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def to_iso(value: Optional[datetime]) -> Optional[str]:
    return value.astimezone(timezone.utc).isoformat() if value else None


def from_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class StateStore:
    """Thread-safe wrapper around one SQLite database."""

    def __init__(self, path: str = "siem_pulse.db", keep_days: int = 90):
        self.path = path
        self.keep_days = keep_days
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @classmethod
    def from_config(cls, config: dict) -> "StateStore":
        cfg = config.get("state", {}) or {}
        return cls(cfg.get("path", "siem_pulse.db"), int(cfg.get("keep_days", 90)))

    @contextmanager
    def _tx(self):
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self):
        with self._lock:
            self._conn.close()

    # ─── Runs ─────────────────────────────────────────────────────────────────

    def start_run(self, scope: str) -> int:
        with self._tx() as c:
            cur = c.execute("INSERT INTO runs (started_at, scope) VALUES (?, ?)", (to_iso(utcnow()), scope))
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, results: List[Dict[str, Any]], duration_seconds: float):
        counts = {"healthy": 0, "stale": 0, "error": 0}
        suppressed = 0
        for r in results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
            suppressed += 1 if r.get("suppressed") else 0
        with self._tx() as c:
            c.execute(
                "UPDATE runs SET finished_at=?, total=?, healthy=?, stale=?, error=?, suppressed=?, "
                "duration_seconds=? WHERE id=?",
                (to_iso(utcnow()), len(results), counts["healthy"], counts["stale"], counts["error"],
                 suppressed, duration_seconds, run_id),
            )
            c.executemany(
                "INSERT INTO results (run_id, device_key, device_name, ip_address, client_name, siem_platform,"
                " criticality, status, suppressed, last_log_time, hours_since_last_log, error, checked_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(run_id, r["device_key"], r.get("device_name"), r.get("ip_address"), r.get("client_name"),
                  r.get("siem_platform"), r.get("criticality"), r["status"], r.get("suppressed"),
                  r.get("last_log_time"), r.get("hours_since_last_log"), r.get("error"), r.get("checked_at"))
                 for r in results],
            )
            if self.keep_days:
                cutoff = to_iso(utcnow() - timedelta(days=self.keep_days))
                old = "SELECT id FROM runs WHERE started_at < ?"
                c.execute(f"DELETE FROM results WHERE run_id IN ({old})", (cutoff,))
                c.execute("DELETE FROM runs WHERE started_at < ?", (cutoff,))
                c.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))

    def recent_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def last_run(self) -> Optional[Dict[str, Any]]:
        runs = self.recent_runs(1)
        return runs[0] if runs else None

    def run_results(self, run_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM results WHERE run_id=?", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    # ─── Device state ─────────────────────────────────────────────────────────

    def get_states(self, keys: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            if keys is None:
                rows = self._conn.execute("SELECT * FROM device_state").fetchall()
            else:
                keys = list(keys)
                rows = []
                for i in range(0, len(keys), 500):
                    chunk = keys[i:i + 500]
                    rows += self._conn.execute(
                        f"SELECT * FROM device_state WHERE device_key IN ({','.join('?' * len(chunk))})", chunk
                    ).fetchall()
        states = {}
        for row in rows:
            state = dict(row)
            state["tickets"] = json.loads(state.get("tickets") or "{}")
            states[state["device_key"]] = state
        return states

    def update_states(self, results: List[Dict[str, Any]], previous: Dict[str, Dict[str, Any]]):
        """Write each device's current status; `since` changes only when the status group changes."""
        now = to_iso(utcnow())
        rows = []
        for r in results:
            prev = previous.get(r["device_key"])
            is_issue = r["status"] in ISSUE_STATUSES
            was_issue = bool(prev) and prev["status"] in ISSUE_STATUSES
            changed = prev is None or is_issue != was_issue
            since = now if changed else prev["since"]
            alerted = 0 if (changed or not is_issue) else prev["alerted"]
            last_alert = None if not is_issue and changed else (prev or {}).get("last_alert_at")
            alert_count = 0 if changed else (prev or {}).get("alert_count", 0)
            tickets = json.dumps((prev or {}).get("tickets", {}))
            rows.append((
                r["device_key"], r.get("device_name"), r.get("ip_address"), r.get("client_name"),
                r.get("siem_platform"), r.get("criticality"), r["status"], since, r.get("checked_at") or now,
                r.get("last_log_time"), r.get("error"), r.get("suppressed"), alerted, last_alert, alert_count,
                tickets,
            ))
        with self._tx() as c:
            c.executemany(
                "INSERT OR REPLACE INTO device_state (device_key, device_name, ip_address, client_name,"
                " siem_platform, criticality, status, since, last_checked_at, last_log_time, error, suppressed,"
                " alerted, last_alert_at, alert_count, tickets) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )

    def mark_alerted(self, keys: Iterable[str]):
        now = to_iso(utcnow())
        with self._tx() as c:
            c.executemany(
                "UPDATE device_state SET alerted=1, last_alert_at=?, alert_count=alert_count+1 WHERE device_key=?",
                [(now, k) for k in keys],
            )

    def set_ticket(self, key: str, channel: str, reference: Optional[str]):
        """Remember (or forget, with None) a ticket/incident id for a device and channel."""
        with self._tx() as c:
            row = c.execute("SELECT tickets FROM device_state WHERE device_key=?", (key,)).fetchone()
            tickets = json.loads(row["tickets"] or "{}") if row else {}
            if reference is None:
                tickets.pop(channel, None)
            else:
                tickets[channel] = reference
            c.execute("UPDATE device_state SET tickets=? WHERE device_key=?", (json.dumps(tickets), key))

    def get_ticket(self, key: str, channel: str) -> Optional[str]:
        state = self.get_states([key]).get(key)
        return (state or {}).get("tickets", {}).get(channel)

    def open_issues(self) -> List[Dict[str, Any]]:
        return [s for s in self.get_states().values() if s["status"] in ISSUE_STATUSES]

    # ─── Snoozes ──────────────────────────────────────────────────────────────

    def snooze(self, key: str, device_name: str, until: datetime, reason: str = ""):
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO snoozes (device_key, device_name, until, reason, created_at)"
                " VALUES (?,?,?,?,?)",
                (key, device_name, to_iso(until), reason, to_iso(utcnow())),
            )

    def unsnooze(self, key: str) -> bool:
        with self._tx() as c:
            return c.execute("DELETE FROM snoozes WHERE device_key=?", (key,)).rowcount > 0

    def active_snoozes(self) -> Dict[str, Dict[str, Any]]:
        now = to_iso(utcnow())
        with self._tx() as c:
            c.execute("DELETE FROM snoozes WHERE until <= ?", (now,))
            rows = c.execute("SELECT * FROM snoozes").fetchall()
        return {r["device_key"]: dict(r) for r in rows}

    # ─── Metrics (Phase 4) ────────────────────────────────────────────────────

    def add_metrics(self, samples: List[Dict[str, Any]]):
        now = to_iso(utcnow())
        with self._tx() as c:
            c.executemany(
                "INSERT INTO metrics (device_key, ts, events_per_hour, unparsed_ratio, max_skew_seconds, log_types)"
                " VALUES (?,?,?,?,?,?)",
                [(s["device_key"], s.get("ts") or now, s.get("events_per_hour"), s.get("unparsed_ratio"),
                  s.get("max_skew_seconds"), json.dumps(sorted(s.get("log_types") or [])))
                 for s in samples],
            )

    def metric_history(self, key: str, days: int = 7) -> List[Dict[str, Any]]:
        cutoff = to_iso(utcnow() - timedelta(days=days))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM metrics WHERE device_key=? AND ts >= ? ORDER BY ts", (key, cutoff)
            ).fetchall()
        history = []
        for row in rows:
            item = dict(row)
            item["log_types"] = json.loads(item.get("log_types") or "[]")
            history.append(item)
        return history

    # ─── Meta ─────────────────────────────────────────────────────────────────

    def get_meta(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str):
        with self._tx() as c:
            c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
