# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
Shared pieces for alert channels: the Channel base class, an HTTP helper and
text formatting used by every channel.

Two kinds of channel:
    summary    one message per batch (email, Slack, Teams, webhook)
    per-device one incident/ticket per device (PagerDuty, Opsgenie, ServiceNow,
               Jira); opened on `new`, updated on `reminders`, closed on
               `recovered`. Digests are not sent to per-device channels.
"""

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..alert_policy import AlertBatch
from ..credentials import get_secret


class ChannelError(Exception):
    """A channel could not deliver its message."""


class Channel:
    type_name = ""
    per_device = False

    def __init__(self, channel_id: str, cfg: dict, config: dict, store=None):
        self.id = channel_id
        self.cfg = cfg or {}
        self.config = config
        self.store = store
        self.timeout = self.cfg.get("timeout_seconds", 15)
        self.verify = self.cfg.get("verify_ssl", True)
        self.logger = logging.getLogger(f"siem_pulse.channels.{channel_id}")

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def secret(self, cfg_key: str, default_name: str) -> Optional[str]:
        """Read the secret named by cfg[cfg_key] (default `default_name`)."""
        return get_secret(self.config, self.cfg.get(cfg_key, default_name))

    def http(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        try:
            response = requests.request(method, url, **kwargs)
        except requests.exceptions.RequestException as e:
            raise ChannelError(f"{self.id}: request to {url} failed: {e}") from e
        if not 200 <= response.status_code < 300:
            body = (response.text or "")[:300]
            raise ChannelError(f"{self.id}: HTTP {response.status_code} from {url}: {body}")
        return response

    def send(self, batch: AlertBatch) -> List[str]:
        """Deliver the batch. Returns the device keys it notified about."""
        raise NotImplementedError


# ─── Formatting ───────────────────────────────────────────────────────────────

SECTION_TITLES = {
    "new": "🆕 New issues",
    "reminders": "🔁 Still open (reminder)",
    "recovered": "✅ Recovered",
    "ongoing": "📋 Open issues",
}


def summary_counts(batch: AlertBatch) -> str:
    if batch.kind == "digest":
        suppressed = sum(1 for i in batch.ongoing if i.get("suppressed"))
        extra = f" ({suppressed} suppressed)" if suppressed else ""
        return f"{len(batch.ongoing)} open issue(s){extra}"
    parts = []
    if batch.new:
        parts.append(f"{len(batch.new)} new")
    if batch.reminders:
        parts.append(f"{len(batch.reminders)} still open")
    if batch.recovered:
        parts.append(f"{len(batch.recovered)} recovered")
    return ", ".join(parts) or "no changes"


def title(batch: AlertBatch) -> str:
    if batch.kind == "digest":
        return f"📋 SIEM Pulse daily digest — {summary_counts(batch)} — {batch.scope}"
    icon = "🚨" if (batch.new or batch.reminders) else "✅"
    return f"{icon} SIEM Pulse — {summary_counts(batch)} — {batch.scope}"


def sections(batch: AlertBatch) -> List[Tuple[str, str, List[Dict[str, Any]]]]:
    """[(group, heading, items)] in display order, non-empty only, items sorted."""
    groups = ["ongoing"] if batch.kind == "digest" else ["new", "reminders", "recovered"]
    out = []
    for group in groups:
        items = sorted(getattr(batch, group),
                       key=lambda i: (str(i.get("client_name") or ""), str(i.get("device_name") or "")))
        if items:
            out.append((group, SECTION_TITLES[group], items))
    return out


def _age(item: Dict[str, Any]) -> str:
    hours = item.get("hours_since_last_log")
    if isinstance(hours, (int, float)):
        return f"{hours:.1f}h ago" if hours < 48 else f"{hours / 24:.1f}d ago"
    return ""


def detail(item: Dict[str, Any], group: str) -> str:
    """The 'why' for one device, e.g. 'last log 2026-10-21 08:00 UTC (30.2h ago, limit 24h)'."""
    if group == "recovered":
        return f"logs flowing again (last log {item.get('last_log_time') or 'now'})"
    if item.get("status") == "error":
        text = f"error: {item.get('error') or 'unknown'}"
    elif item.get("status") == "degraded":
        text = "logs arriving but " + "; ".join(item.get("findings") or ["quality checks failed"])
    else:
        age = _age(item)
        limit = item.get("threshold_hours")
        limit_text = f", limit {limit:g}h" if isinstance(limit, (int, float)) else ""
        text = f"last log {item.get('last_log_time') or 'never'}"
        if age or limit_text:
            text += f" ({age}{limit_text})".replace("(, ", "(")
    if item.get("suppressed"):
        text += f" — 🔕 {item['suppressed']}"
    if item.get("status") != "degraded":
        for finding in item.get("findings") or []:
            text += f" — ⚠️ {finding}"
    return text


def device_label(item: Dict[str, Any]) -> str:
    crit = item.get("criticality")
    crit_text = f" [{crit.upper()}]" if crit and crit != "medium" else ""
    return (f"{item.get('device_name')} ({item.get('ip_address')}) "
            f"{str(item.get('siem_platform') or '').upper()}{crit_text}")


def plain_text(batch: AlertBatch, preview: Optional[str] = None) -> str:
    lines = [title(batch), f"Generated {batch.time_label}", ""]
    for group, heading, items in sections(batch):
        lines.append(f"{heading} ({len(items)})")
        client = None
        for item in items:
            if item.get("client_name") != client:
                client = item.get("client_name")
                lines.append(f"  {client or 'N/A'}")
            lines.append(f"    - {device_label(item)}: {detail(item, group)}")
        lines.append("")
    if preview:
        lines.append(f"Preview affected devices: {preview}")
    return "\n".join(lines)


def preview_command(scope: str) -> str:
    """Command an analyst can run to list the devices in this alert's scope."""
    cmd = "siem-pulse --dry-run"
    for part in (scope or "").split(" | "):
        if part.startswith("SIEM="):
            cmd += f" --siem {part[5:].lower()}"
        elif part.startswith("Client="):
            cmd += f' --client "{part[7:]}"'
    return cmd


def incident_key(item: Dict[str, Any]) -> str:
    """Short stable id for a device outage (PagerDuty dedup_key, Opsgenie alias)."""
    return "siem-pulse-" + hashlib.sha1(str(item.get("device_key")).encode()).hexdigest()[:20]


def jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, float) and value != value:  # NaN
        return None
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


def chunk_lines(lines: List[str], limit: int) -> List[str]:
    """Join lines into chunks no longer than `limit` characters (long lines are cut)."""
    chunks, current = [], ""
    for line in lines:
        line = line if len(line) <= limit else line[: limit - 1] + "…"
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks
