# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
Alert channels.

Define channels under `alerting.channels` in config.yaml, keyed by an id you
choose, and reference those ids from `alerting.routes` / `default_channels`:

    alerting:
      channels:
        soc_email: {type: email, smtp_server: smtp.example.com, sender: soc@example.com,
                    recipients: [soc@example.com], default: true}
        soc_teams: {type: teams, webhook_secret: TEAMS_WEBHOOK_URL}
        oncall:    {type: pagerduty, routing_key_secret: PAGERDUTY_ROUTING_KEY}

The older `alerting.email` and `alerting.slack` blocks still work: when
enabled they become channels named `email` and `slack`.

Third-party channels can be installed as plugins that register a Channel
subclass under the `siem_pulse.channels` entry-point group.
"""

import logging
from importlib.metadata import entry_points
from typing import Dict

from .base import Channel, ChannelError
from .incidents import JiraChannel, OpsgenieChannel, PagerDutyChannel, ServiceNowChannel
from .summary import EmailChannel, SlackChannel, TeamsChannel, WebhookChannel

logger = logging.getLogger(__name__)

CHANNEL_TYPES: Dict[str, type] = {
    cls.type_name: cls
    for cls in (EmailChannel, SlackChannel, TeamsChannel, WebhookChannel,
                PagerDutyChannel, OpsgenieChannel, ServiceNowChannel, JiraChannel)
}
_plugins_loaded = False


def load_channel_plugins():
    """Register Channel classes published under the `siem_pulse.channels` entry point."""
    global _plugins_loaded
    if _plugins_loaded:
        return
    _plugins_loaded = True
    for ep in entry_points(group="siem_pulse.channels"):
        try:
            cls = ep.load()
            CHANNEL_TYPES[ep.name] = cls
            logger.info(f"Loaded channel plugin '{ep.name}' from {ep.value}")
        except Exception as e:
            logger.error(f"Could not load channel plugin '{ep.name}': {e}")


def build_channels(config: dict, store=None) -> Dict[str, Channel]:
    load_channel_plugins()
    cfg = config.get("alerting", {}) or {}
    definitions = {}
    for legacy in ("email", "slack"):
        block = cfg.get(legacy) or {}
        if block.get("enabled", False):
            definitions[legacy] = {**block, "type": legacy}
    for cid, ccfg in (cfg.get("channels") or {}).items():
        if (ccfg or {}).get("enabled", True):
            definitions[cid] = ccfg or {}

    channels = {}
    for cid, ccfg in definitions.items():
        ctype = str(ccfg.get("type", "")).lower()
        if ctype not in CHANNEL_TYPES:
            logger.error(f"Channel '{cid}' has unknown type '{ctype}' (known: {', '.join(sorted(CHANNEL_TYPES))})")
            continue
        channels[cid] = CHANNEL_TYPES[ctype](cid, ccfg, config, store)
    return channels


__all__ = ["Channel", "ChannelError", "CHANNEL_TYPES", "build_channels", "load_channel_plugins"]
