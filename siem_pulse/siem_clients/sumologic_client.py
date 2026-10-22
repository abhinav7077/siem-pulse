# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
sumologic_client.py
===================
Sumo Logic via the Search Job API.

    siem:
      sumologic:
        base_url: "https://api.sumologic.com/api"   # use your deployment, e.g. api.eu.sumologic.com
        lookback_hours: 24
        query: "* | max(_receipttime) as last_seen by _sourcehost"
        host_field: _sourcehost
        time_field: last_seen
        search_timeout_seconds: 300

Credentials: SUMO_ACCESS_ID / SUMO_ACCESS_KEY.

Flow: create a search job, poll until "DONE GATHERING RESULTS", page through
the aggregate records, delete the job.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .base_client import InventoryClient, NonRetryableError, RetryableError, parse_timestamp


class SumoLogicClient(InventoryClient):
    config_key = "sumologic"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = cfg.get("base_url", "https://api.sumologic.com/api").rstrip("/")
        self.query = cfg.get("query", "* | max(_receipttime) as last_seen by _sourcehost")
        self.host_field = cfg.get("host_field", "_sourcehost")
        self.time_field = cfg.get("time_field", "last_seen")
        self.poll_interval = float(cfg.get("search_poll_seconds", 3))
        self.search_timeout = float(cfg.get("search_timeout_seconds", 300))
        self.page_size = int(cfg.get("page_size", 10000))
        self.access_id = self.credential("SUMO_ACCESS_ID")
        self.access_key = self.credential("SUMO_ACCESS_KEY")

    def _call(self, method, path, **kwargs):
        return self._request(method, f"{self.base_url}{path}", auth=(self.access_id, self.access_key),
                             headers={"Accept": "application/json"}, **kwargs)

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        now = datetime.now(tz=timezone.utc)
        start = now - timedelta(hours=self._window_hours())
        job = self._json(self._call("POST", "/v1/search/jobs", json={
            "query": self.query, "from": start.strftime("%Y-%m-%dT%H:%M:%S"),
            "to": now.strftime("%Y-%m-%dT%H:%M:%S"), "timeZone": "UTC", "byReceiptTime": True,
        }), "Sumo Logic")
        job_id = job.get("id")
        if not job_id:
            raise NonRetryableError(f"Sumo Logic did not return a job id: {str(job)[:200]}")
        try:
            record_count = self._wait(job_id)
            inventory, offset = [], 0
            while offset < record_count:
                page = self._json(self._call("GET", f"/v1/search/jobs/{job_id}/records",
                                             params={"offset": offset, "limit": self.page_size}), "Sumo Logic")
                records = page.get("records") or []
                for record in records:
                    fields = {k.lower(): v for k, v in (record.get("map") or {}).items()}
                    host = fields.get(self.host_field.lower(), "")
                    inventory.append({"name": str(host), "identifier": str(host),
                                      "last_seen": parse_timestamp(fields.get(self.time_field.lower()))})
                if not records:
                    break
                offset += len(records)
            return inventory
        finally:
            try:
                self._call("DELETE", f"/v1/search/jobs/{job_id}")
            except Exception as e:
                self.logger.debug(f"Could not delete Sumo Logic job {job_id}: {e}")

    def _wait(self, job_id: str) -> int:
        deadline = time.monotonic() + self.search_timeout
        while True:
            status = self._json(self._call("GET", f"/v1/search/jobs/{job_id}"), "Sumo Logic")
            state = str(status.get("state", "")).upper()
            if state == "DONE GATHERING RESULTS":
                return int(status.get("recordCount", 0))
            if state in ("CANCELLED", "FORCE PAUSED"):
                raise NonRetryableError(f"Sumo Logic search job {job_id} ended: {state}")
            if time.monotonic() >= deadline:
                raise RetryableError(f"Sumo Logic search job {job_id} not done after {self.search_timeout:.0f}s")
            time.sleep(self.poll_interval)
