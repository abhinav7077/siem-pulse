# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
alert_policy.py
===============
Turns check results + the previous state into an AlertBatch, and routes that
batch to channels.

Every unhealthy, unsuppressed device falls into one group:
    new        it just became stale/error (or was never alerted, e.g. a snooze ended)
    reminder   still unhealthy, already alerted, and `repeat_after_hours` has passed
    ongoing    still unhealthy and already alerted recently (not re-sent)
and healthy devices that had been alerted become:
    recovered  logs are flowing again

config.yaml:

    alerting:
      mode: changes            # changes (default) | every_run (old behaviour: every issue, every run)
      repeat_after_hours: 24   # re-send still-open issues this often (0 = never)
      notify_recovered: true
      default_channels: [email, slack]     # devices that match no route
      routes:                               # first match wins unless continue: true
        - match: {client_name: "Acme Corp"}
          channels: [acme_email, acme_teams]
        - match: {criticality: critical}
          channels: [pagerduty]
          continue: true
      digest:
        enabled: true
        time: "08:00"          # daily, in `timezone`
        timezone: "UTC"
        channels: [email]      # defaults to default_channels
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from .state_store import ISSUE_STATUSES, from_iso
from .suppression import matches

GROUPS = ("new", "reminders", "recovered", "ongoing")


@dataclass
class AlertBatch:
    kind: str = "alert"                       # alert | digest
    scope: str = "ALL devices"
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    new: List[Dict[str, Any]] = field(default_factory=list)
    reminders: List[Dict[str, Any]] = field(default_factory=list)
    recovered: List[Dict[str, Any]] = field(default_factory=list)
    ongoing: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def issues(self) -> List[Dict[str, Any]]:
        """Issues this batch should notify about."""
        if self.kind == "digest":
            return self.ongoing
        return self.new + self.reminders

    @property
    def stale(self) -> List[Dict[str, Any]]:
        return [i for i in self.issues if i.get("status") == "stale"]

    @property
    def errors(self) -> List[Dict[str, Any]]:
        return [i for i in self.issues if i.get("status") == "error"]

    def is_empty(self) -> bool:
        if self.kind == "digest":
            return not self.ongoing
        return not (self.new or self.reminders or self.recovered)

    def all_items(self):
        for group in GROUPS:
            for item in getattr(self, group):
                yield group, item

    def subset(self, keep: Callable[[str, Dict[str, Any]], bool]) -> "AlertBatch":
        part = AlertBatch(kind=self.kind, scope=self.scope, generated_at=self.generated_at)
        for group, item in self.all_items():
            if keep(group, item):
                getattr(part, group).append(item)
        return part

    @property
    def time_label(self) -> str:
        return self.generated_at.strftime("%Y-%m-%d %H:%M UTC")


def classify(
    results: List[Dict[str, Any]],
    previous: Dict[str, Dict[str, Any]],
    config: dict,
    scope: str = "ALL devices",
    now: Optional[datetime] = None,
) -> AlertBatch:
    now = now or datetime.now(tz=timezone.utc)
    cfg = config.get("alerting", {}) or {}
    mode = str(cfg.get("mode", "changes")).lower()
    repeat_hours = float(cfg.get("repeat_after_hours", 24) or 0)
    notify_recovered = cfg.get("notify_recovered", True)

    batch = AlertBatch(scope=scope, generated_at=now)
    for r in results:
        prev = previous.get(r.get("device_key"))
        is_issue = r["status"] in ISSUE_STATUSES
        was_issue = bool(prev) and prev["status"] in ISSUE_STATUSES
        item = dict(r)
        item["since"] = (prev or {}).get("since") if was_issue and is_issue else now.isoformat()
        item["previous_status"] = (prev or {}).get("status")

        if is_issue:
            already_alerted = was_issue and bool(prev.get("alerted"))
            if r.get("suppressed"):
                batch.ongoing.append(item)
            elif not already_alerted:
                batch.new.append(item)
            elif mode == "every_run":
                batch.reminders.append(item)
            else:
                last = from_iso(prev.get("last_alert_at"))
                if repeat_hours and (last is None or now - last >= timedelta(hours=repeat_hours)):
                    batch.reminders.append(item)
                else:
                    batch.ongoing.append(item)
        elif was_issue and prev.get("alerted") and notify_recovered:
            batch.recovered.append(item)
    return batch


def channel_targets(item: Dict[str, Any], config: dict) -> List[str]:
    """Which channel ids an item goes to, according to routes."""
    cfg = config.get("alerting", {}) or {}
    targets: List[str] = []
    matched = False
    for route in cfg.get("routes") or []:
        if matches(item, route.get("match")):
            matched = True
            for channel in route.get("channels") or []:
                if channel not in targets:
                    targets.append(channel)
            if not route.get("continue", False):
                break
    if not matched:
        targets = list(default_channel_ids(config))
    return targets


def default_channel_ids(config: dict) -> List[str]:
    cfg = config.get("alerting", {}) or {}
    if cfg.get("default_channels") is not None:
        return list(cfg["default_channels"])
    ids = [legacy for legacy in ("email", "slack") if (cfg.get(legacy) or {}).get("enabled", False)]
    ids += [cid for cid, ccfg in (cfg.get("channels") or {}).items() if (ccfg or {}).get("default", False)]
    return ids


def route(batch: AlertBatch, config: dict) -> Dict[str, AlertBatch]:
    """Split a batch into one batch per channel id."""
    if batch.kind == "digest":
        digest_cfg = (config.get("alerting", {}) or {}).get("digest", {}) or {}
        ids = digest_cfg.get("channels") or default_channel_ids(config)
        return {cid: batch for cid in ids}

    per_item = {}
    for _group, item in batch.all_items():
        per_item[id(item)] = channel_targets(item, config)
    channel_ids = []
    for targets in per_item.values():
        for cid in targets:
            if cid not in channel_ids:
                channel_ids.append(cid)
    return {
        cid: batch.subset(lambda _g, item, cid=cid: cid in per_item[id(item)])
        for cid in channel_ids
    }


def digest_due(config: dict, last_sent: Optional[str], now: Optional[datetime] = None) -> bool:
    """True once per day, at or after the configured local time."""
    cfg = ((config.get("alerting", {}) or {}).get("digest", {}) or {})
    if not cfg.get("enabled", False):
        return False
    now = now or datetime.now(tz=timezone.utc)
    tz = timezone.utc
    if cfg.get("timezone"):
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(cfg["timezone"])
    local = now.astimezone(tz)
    hours, minutes = str(cfg.get("time", "08:00")).split(":")[:2]
    due_at = local.replace(hour=int(hours), minute=int(minutes), second=0, microsecond=0)
    if local < due_at:
        return False
    last = from_iso(last_sent)
    return last is None or last.astimezone(tz) < due_at


def digest_batch(open_states: List[Dict[str, Any]], scope: str = "ALL devices") -> AlertBatch:
    batch = AlertBatch(kind="digest", scope=scope)
    for state in open_states:
        batch.ongoing.append({
            **state,
            "hours_since_last_log": None,
            "error": state.get("error"),
        })
    return batch
