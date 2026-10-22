# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
sentinel_client.py
==================
Microsoft Sentinel (Log Analytics workspace) via the Log Analytics query API.

    siem:
      sentinel:
        workspace_id: "00000000-0000-0000-0000-000000000000"
        tenant_id: "11111111-1111-1111-1111-111111111111"
        lookback_hours: 72
        query: |         # optional — must return name_column, ip_column, time_column
          ...
        name_column: Name
        ip_column: Ip
        time_column: LastSeen

Credentials: an Entra ID app registration with "Log Analytics Reader" on the
workspace — SENTINEL_CLIENT_ID and SENTINEL_CLIENT_SECRET.

The default query looks at the common log tables (CEF/Syslog/Windows/agent
heartbeats) and returns the newest TimeGenerated per computer/device.
"""

import time
from typing import Any, Dict, List, Optional

from .base_client import InventoryClient, NonRetryableError, parse_timestamp

DEFAULT_QUERY = """union isfuzzy=true
  (CommonSecurityLog | summarize LastSeen=max(TimeGenerated) by Name=coalesce(DeviceName, Computer), Ip=DeviceAddress),
  (Syslog | summarize LastSeen=max(TimeGenerated) by Name=Computer, Ip=HostIP),
  (SecurityEvent | extend Ip="" | summarize LastSeen=max(TimeGenerated) by Name=Computer, Ip),
  (WindowsEvent | extend Ip="" | summarize LastSeen=max(TimeGenerated) by Name=Computer, Ip),
  (Heartbeat | summarize LastSeen=max(TimeGenerated) by Name=Computer, Ip=ComputerIP)
| summarize LastSeen=max(LastSeen) by Name, Ip"""


class SentinelClient(InventoryClient):
    config_key = "sentinel"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.workspace_id = cfg.get("workspace_id", "")
        self.tenant_id = cfg.get("tenant_id", "")
        self.base_url = cfg.get("base_url", "https://api.loganalytics.io").rstrip("/")
        self.login_url = cfg.get("login_url", "https://login.microsoftonline.com").rstrip("/")
        self.query = cfg.get("query") or DEFAULT_QUERY
        self.name_column = cfg.get("name_column", "Name")
        self.ip_column = cfg.get("ip_column", "Ip")
        self.time_column = cfg.get("time_column", "LastSeen")
        self.client_id = self.credential("SENTINEL_CLIENT_ID")
        self.client_secret = self.credential("SENTINEL_CLIENT_SECRET")
        self._token, self._token_expires = "", 0.0

    def _access_token(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        if not self.tenant_id:
            raise NonRetryableError("siem.sentinel.tenant_id is required")
        response = self._request(
            "POST", f"{self.login_url}/{self.tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret, "scope": f"{self.base_url}/.default"},
        )
        body = self._json(response, "Entra ID")
        self._token = body.get("access_token", "")
        self._token_expires = time.time() + float(body.get("expires_in", 3600))
        if not self._token:
            raise NonRetryableError("Entra ID did not return an access token")
        return self._token

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        if not self.workspace_id:
            raise NonRetryableError("siem.sentinel.workspace_id is required")
        response = self._request(
            "POST", f"{self.base_url}/v1/workspaces/{self.workspace_id}/query",
            json={"query": self.query, "timespan": f"PT{int(self._window_hours())}H"},
            headers={"Authorization": f"Bearer {self._access_token()}"},
        )
        body = self._json(response, "Sentinel")
        tables = body.get("tables") or []
        if not tables:
            raise NonRetryableError(f"Sentinel query returned no tables: {str(body)[:200]}")
        columns = [c.get("name") for c in tables[0].get("columns", [])]
        missing = [c for c in (self.name_column, self.time_column) if c not in columns]
        if missing:
            raise NonRetryableError(f"Sentinel query result is missing columns {missing} (got {columns})")
        inventory = []
        for row in tables[0].get("rows", []):
            record = dict(zip(columns, row, strict=False))
            inventory.append({
                "name": str(record.get(self.name_column) or ""),
                "identifier": str(record.get(self.ip_column) or record.get(self.name_column) or ""),
                "last_seen": parse_timestamp(record.get(self.time_column)),
            })
        return inventory
