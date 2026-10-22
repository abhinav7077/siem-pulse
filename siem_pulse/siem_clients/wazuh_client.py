# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
wazuh_client.py
===============
Wazuh manager API (port 55000).

    siem:
      wazuh:
        base_url: "https://wazuh.example.com:55000"
        page_size: 500

Credentials: WAZUH_USER / WAZUH_PASS (an API user, not a dashboard user).

Uses each agent's `lastKeepAlive`: the last time the agent checked in. This
shows the agent is alive and connected; it does not prove every log type is
arriving (see Phase 4 volume checks for that).
"""

import time
from typing import Any, Dict, List, Optional

from .base_client import InventoryClient, NonRetryableError, parse_timestamp


class WazuhClient(InventoryClient):
    config_key = "wazuh"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = cfg.get("base_url", "https://wazuh.example.com:55000").rstrip("/")
        self.page_size = int(cfg.get("page_size", 500))
        self.username = self.credential("WAZUH_USER")
        self.password = self.credential("WAZUH_PASS")
        self._token, self._token_time = "", 0.0

    def _jwt(self) -> str:
        if self._token and time.time() - self._token_time < 800:   # tokens last 900s by default
            return self._token
        response = self._request("POST", f"{self.base_url}/security/user/authenticate",
                                 auth=(self.username, self.password))
        self._token = (self._json(response, "Wazuh").get("data") or {}).get("token", "")
        if not self._token:
            raise NonRetryableError("Wazuh did not return a token")
        self._token_time = time.time()
        return self._token

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        inventory, offset = [], 0
        while True:
            response = self._request(
                "GET", f"{self.base_url}/agents",
                params={"select": "id,name,ip,lastKeepAlive,status", "limit": self.page_size, "offset": offset},
                headers={"Authorization": f"Bearer {self._jwt()}"},
            )
            data = self._json(response, "Wazuh").get("data") or {}
            items = data.get("affected_items") or []
            for agent in items:
                if str(agent.get("id")) == "000":
                    continue  # the manager itself
                inventory.append({"name": str(agent.get("name") or ""), "identifier": str(agent.get("ip") or ""),
                                  "last_seen": parse_timestamp(agent.get("lastKeepAlive"))})
            offset += len(items)
            if not items or offset >= int(data.get("total_affected_items", 0)):
                return inventory
