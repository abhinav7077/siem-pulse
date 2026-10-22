# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
suppression.py
==============
Decides which device results should NOT raise alerts right now.

A suppressed device is still checked and reported (marked 🔕), but no alert
is sent. When the suppression ends and the device is still unhealthy, it is
alerted as a new issue.

Three sources, first match wins:
  1. `snooze_until` inventory column
  2. manual snoozes:  siem-pulse --snooze "fw-01" --until 2026-10-25T08:00 --reason "RMA"
  3. maintenance windows in config.yaml:

    maintenance_windows:
      - name: "Acme patch night"
        match: {client_name: "Acme Corp"}          # same match keys as alert routes
        weekly: {days: [sat], start: "22:00", end: "04:00", timezone: "Europe/London"}
      - name: "DC migration"
        match: {device_name: "dc-*"}
        start: "2026-11-02T18:00:00Z"              # one-off window
        end:   "2026-11-03T06:00:00Z"
"""

import fnmatch
from datetime import datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

from .excel_reader import parse_datetime

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
MATCH_KEYS = ("client_name", "siem_platform", "criticality", "device_name", "device_type", "auth_ref",
              "ip_address", "status")


def matches(item: Dict[str, Any], rule: Optional[Dict[str, Any]]) -> bool:
    """
    True when every key in `rule` matches the item. Values may be a string or a
    list; glob patterns (*, ?) work; comparisons ignore case. An empty rule
    matches everything.
    """
    for key, expected in (rule or {}).items():
        actual = str(item.get(key) or "").lower()
        options = expected if isinstance(expected, (list, tuple, set)) else [expected]
        if not any(fnmatch.fnmatchcase(actual, str(o).lower()) for o in options):
            return False
    return True


def _parse_clock(value: str) -> time:
    hours, minutes = str(value).strip().split(":")[:2]
    return time(int(hours), int(minutes))


def in_weekly_window(weekly: Dict[str, Any], now: datetime) -> bool:
    """Weekly window; an end earlier than the start runs past midnight into the next day."""
    tz = timezone.utc
    if weekly.get("timezone") and ZoneInfo:
        tz = ZoneInfo(weekly["timezone"])
    local = now.astimezone(tz)
    days = [str(d).lower()[:3] for d in weekly.get("days", DAYS)]
    start, end = _parse_clock(weekly.get("start", "00:00")), _parse_clock(weekly.get("end", "23:59"))
    today = DAYS[local.weekday()]
    yesterday = DAYS[(local.weekday() - 1) % 7]
    clock = local.time()
    if start <= end:
        return today in days and start <= clock < end
    # Overnight, e.g. Sat 22:00 -> Sun 04:00
    return (today in days and clock >= start) or (yesterday in days and clock < end)


def active_window(windows: Iterable[Dict[str, Any]], item: Dict[str, Any], now: datetime) -> Optional[str]:
    for window in windows or []:
        if not matches(item, window.get("match")):
            continue
        name = window.get("name") or "maintenance window"
        if window.get("weekly") and in_weekly_window(window["weekly"], now):
            return name
        start, end = window.get("start"), window.get("end")
        if start and end:
            start_dt, end_dt = parse_datetime(str(start)), parse_datetime(str(end))
            if start_dt and end_dt and start_dt <= now < end_dt:
                return name
    return None


def apply_suppression(
    results: List[Dict[str, Any]],
    config: dict,
    snoozes: Dict[str, Dict[str, Any]],
    now: Optional[datetime] = None,
) -> int:
    """Set result['suppressed'] to a reason (or None). Returns how many are suppressed."""
    now = now or datetime.now(tz=timezone.utc)
    windows = config.get("maintenance_windows") or []
    count = 0
    for r in results:
        reason = None
        until = r.get("snooze_until")
        if isinstance(until, datetime) and now < until:
            reason = f"snoozed until {until.strftime('%Y-%m-%d %H:%M UTC')} (inventory)"
        elif r.get("device_key") in snoozes:
            snooze = snoozes[r["device_key"]]
            note = f": {snooze['reason']}" if snooze.get("reason") else ""
            reason = f"snoozed until {snooze['until'][:16].replace('T', ' ')} UTC{note}"
        else:
            window = active_window(windows, r, now)
            if window:
                reason = f"maintenance: {window}"
        r["suppressed"] = reason
        count += 1 if reason else 0
    return count


def parse_until(value: str, now: Optional[datetime] = None) -> datetime:
    """Accept an absolute time or a duration like '4h', '2d', '30m'."""
    now = now or datetime.now(tz=timezone.utc)
    text = str(value).strip().lower()
    units = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if text[:-1].replace(".", "", 1).isdigit() and text[-1] in units:
        return now + timedelta(**{units[text[-1]]: float(text[:-1])})
    parsed = parse_datetime(value)
    if not parsed:
        raise ValueError(f"Cannot understand --until '{value}' (use 4h, 2d or 2026-10-25T08:00)")
    return parsed
