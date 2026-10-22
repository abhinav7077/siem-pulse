# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
elastic_client.py
=================
Elastic Security / Elasticsearch / OpenSearch via the _search API.

    siem:
      elastic:
        base_url: "https://elastic.example.com:9200"
        index: "logs-*,filebeat-*,winlogbeat-*"
        host_field: host.name        # keyword field holding the device name
        ip_field: host.ip            # optional — "" to group by name only
        time_field: "@timestamp"
        lookback_hours: 72
        page_size: 1000

Credentials: ELASTIC_API_KEY (base64 "id:key", sent as "ApiKey ..."), or
ELASTIC_USER + ELASTIC_PASS.

Uses a composite aggregation (paged with after_key) with max(time_field) per
host, so one query covers every device.
"""

import copy
from typing import Any, Dict, List, Optional

from .base_client import InventoryClient, epoch_to_datetime


class ElasticClient(InventoryClient):
    config_key = "elastic"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = cfg.get("base_url", "https://elastic.example.com:9200").rstrip("/")
        self.index = cfg.get("index", "logs-*")
        self.host_field = cfg.get("host_field", "host.name")
        self.ip_field = cfg.get("ip_field", "host.ip")
        self.time_field = cfg.get("time_field", "@timestamp")
        self.page_size = int(cfg.get("page_size", 1000))
        self.api_key = self.optional_credential("ELASTIC_API_KEY")
        if not self.api_key:
            self.username = self.credential("ELASTIC_USER")
            self.password = self.credential("ELASTIC_PASS")

    def _auth(self) -> Dict[str, Any]:
        if self.api_key:
            return {"headers": {"Authorization": f"ApiKey {self.api_key}"}}
        return {"auth": (self.username, self.password)}

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        sources = [{"name": {"terms": {"field": self.host_field, "missing_bucket": True}}}]
        if self.ip_field:
            sources.append({"ip": {"terms": {"field": self.ip_field, "missing_bucket": True}}})
        body: Dict[str, Any] = {
            "size": 0,
            "query": {"range": {self.time_field: {"gte": f"now-{int(self._window_hours())}h"}}},
            "aggs": {"hosts": {
                "composite": {"size": self.page_size, "sources": sources},
                "aggs": {"last_seen": {"max": {"field": self.time_field}}},
            }},
        }
        inventory = []
        while True:
            response = self._request("POST", f"{self.base_url}/{self.index}/_search",
                                     json=copy.deepcopy(body), **self._auth())
            agg = (self._json(response, "Elastic").get("aggregations") or {}).get("hosts") or {}
            buckets = agg.get("buckets") or []
            for bucket in buckets:
                key = bucket.get("key") or {}
                value = (bucket.get("last_seen") or {}).get("value")
                inventory.append({
                    "name": str(key.get("name") or ""),
                    "identifier": str(key.get("ip") or key.get("name") or ""),
                    "last_seen": epoch_to_datetime(value) if value else None,
                })
            after = agg.get("after_key")
            if not after or len(buckets) < self.page_size:
                return inventory
            body["aggs"]["hosts"]["composite"]["after"] = after
