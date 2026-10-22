# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
splunk_client.py
================
Splunk Enterprise / Splunk Cloud via the REST API (management port 8089).

    siem:
      splunk:
        base_url: "https://splunk.example.com:8089"
        lookback_hours: 72
        # One search lists the newest event per host. Must return the fields
        # named by host_field and time_field. {hours} is replaced.
        search: "| tstats latest(_time) as last_seen where index=* earliest=-{hours}h by host"
        host_field: host
        time_field: last_seen

Credentials: SPLUNK_TOKEN (authentication token, sent as Bearer), or
SPLUNK_USER + SPLUNK_PASS when no token is set.

The `host` value is matched against both the device IP and the device name.
"""

import json
from typing import Any, Dict, List, Optional

from .base_client import InventoryClient, NonRetryableError, parse_timestamp

DEFAULT_SEARCH = "| tstats latest(_time) as last_seen where index=* earliest=-{hours}h by host"
METRICS_SEARCH = (
    "| tstats count max(_indextime) as indexed max(_time) as latest "
    "where index=* earliest=-{minutes}m by host sourcetype"
)


class SplunkClient(InventoryClient):
    config_key = "splunk"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = cfg.get("base_url", "https://splunk.example.com:8089").rstrip("/")
        self.search = cfg.get("search", DEFAULT_SEARCH)
        self.host_field = cfg.get("host_field", "host")
        self.time_field = cfg.get("time_field", "last_seen")
        self.token = self.optional_credential("SPLUNK_TOKEN")
        if not self.token:
            self.username = self.credential("SPLUNK_USER")
            self.password = self.credential("SPLUNK_PASS")

    supports_metrics = True

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        inventory = []
        for result in self._export(self.search.format(hours=int(self._window_hours()))):
            host = self._host(result)
            inventory.append({"identifier": host, "name": host,
                              "last_seen": parse_timestamp(result.get(self.time_field))})
        return inventory

    def _host(self, result: Dict[str, Any]) -> str:
        host = result.get(self.host_field)
        if isinstance(host, list):
            host = host[0] if host else ""
        return str(host or "")

    def _fetch_metrics(self, window_hours: float) -> List[Dict[str, Any]]:
        """Event count and sourcetypes per host; skew = newest index time - newest event time."""
        query = self.platform_cfg.get("metrics_search", METRICS_SEARCH).format(minutes=max(1, int(window_hours * 60)))
        per_host: Dict[str, Dict[str, Any]] = {}
        for result in self._export(query):
            host = self._host(result)
            entry = per_host.setdefault(host, {"name": host, "identifier": host, "events": 0,
                                               "log_types": set(), "max_skew_seconds": None})
            entry["events"] += int(float(result.get("count") or 0))
            if result.get("sourcetype"):
                entry["log_types"].add(str(result["sourcetype"]))
            try:
                skew = abs(float(result["indexed"]) - float(result["latest"]))
                entry["max_skew_seconds"] = max(entry["max_skew_seconds"] or 0, skew)
            except (KeyError, TypeError, ValueError):
                pass
        for entry in per_host.values():
            entry["log_types"] = sorted(entry["log_types"])
        return list(per_host.values())

    def _export(self, query: str) -> List[Dict[str, Any]]:
        """Run a search through the export endpoint and return the result rows."""
        if not query.lstrip().startswith(("|", "search ")):
            query = "search " + query
        kwargs: Dict[str, Any] = {"data": {"search": query, "output_mode": "json"}}
        if self.token:
            kwargs["headers"] = {"Authorization": f"Bearer {self.token}"}
        else:
            kwargs["auth"] = (self.username, self.password)
        response = self._request("POST", f"{self.base_url}/services/search/jobs/export", **kwargs)

        rows = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError as e:
                raise NonRetryableError(f"Splunk returned non-JSON output: {line[:200]}") from e
            if row.get("messages") and not row.get("result"):
                for message in row["messages"]:
                    if message.get("type") in ("FATAL", "ERROR"):
                        raise NonRetryableError(f"Splunk search error: {message.get('text')}")
            if row.get("result"):
                rows.append(row["result"])
        return rows
