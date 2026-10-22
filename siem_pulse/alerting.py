# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
alerting.py
===========
Sends an AlertBatch to every channel its routes select.

    batch  = alert_policy.classify(results, previous_state, config)
    sent   = AlertManager(config, store).dispatch(batch)

A failing channel is logged and does not stop the others. Devices count as
"alerted" once at least one channel delivered them, so an issue that could
not be delivered anywhere is retried on the next run.

See alert_policy.py for routes and digests, and channels/ for channel types.
"""

import logging
from typing import Any, Dict, List, Optional, Set

from .alert_policy import AlertBatch, route
from .channels import build_channels
from .channels.base import preview_command

logger = logging.getLogger(__name__)


class AlertManager:
    """Dispatches alerts via configured channels."""

    def __init__(self, config: dict, store=None):
        self.config = config
        self.store = store
        self.channels = build_channels(config, store)

    def dispatch(self, batch: AlertBatch) -> Dict[str, bool]:
        """Send a batch. Returns {channel_id: delivered}."""
        if batch.is_empty():
            logger.info("Nothing new to alert on.")
            return {}

        outcome: Dict[str, bool] = {}
        delivered: Set[str] = set()
        for channel_id, part in route(batch, self.config).items():
            if part.is_empty():
                continue
            channel = self.channels.get(channel_id)
            if channel is None:
                logger.error(f"Route points to unknown or disabled channel '{channel_id}'")
                outcome[channel_id] = False
                continue
            if batch.kind == "digest" and channel.per_device:
                continue
            try:
                delivered.update(channel.send(part) or [])
                outcome[channel_id] = True
            except Exception as e:
                logger.error(f"Channel '{channel_id}' failed: {e}")
                outcome[channel_id] = False

        if not outcome:
            logger.warning("No alert channels are configured for these devices (see alerting.routes).")
        if self.store and batch.kind == "alert" and delivered:
            self.store.mark_alerted(delivered)
        ok = [c for c, success in outcome.items() if success]
        failed = [c for c, success in outcome.items() if not success]
        logger.info(
            f"Alerts: {len(batch.new)} new, {len(batch.reminders)} reminders, {len(batch.recovered)} recovered "
            f"| channels ok: {ok} failed: {failed}"
        )
        return outcome

    # ─── Backwards compatible helpers ─────────────────────────────────────────

    def send_alert(
        self,
        stale_devices: List[Dict[str, Any]],
        error_devices: List[Dict[str, Any]],
        filter_siem: Optional[str] = None,
        filter_client: Optional[str] = None,
    ) -> Dict[str, bool]:
        """Old API: alert on these devices as new issues."""
        batch = AlertBatch(scope=self._scope_label(filter_siem, filter_client))
        batch.new = list(stale_devices) + list(error_devices)
        return self.dispatch(batch)

    @staticmethod
    def _preview_command(filter_siem: Optional[str], filter_client: Optional[str]) -> str:
        return preview_command(AlertManager._scope_label(filter_siem, filter_client))

    @staticmethod
    def _scope_label(filter_siem: Optional[str], filter_client: Optional[str]) -> str:
        parts = []
        if filter_siem:
            parts.append(f"SIEM={filter_siem.upper()}")
        if filter_client:
            parts.append(f"Client={filter_client}")
        return " | ".join(parts) if parts else "ALL devices"
