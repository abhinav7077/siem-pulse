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
        self.log_type_field = cfg.get("log_type_field", "event.dataset")
        self.ingest_time_field = cfg.get("ingest_time_field", "event.ingested")
        self.api_key = self.optional_credential("ELASTIC_API_KEY")
        if not self.api_key:
            self.username = self.credential("ELASTIC_USER")
            self.password = self.credential("ELASTIC_PASS")

    def _auth(self) -> Dict[str, Any]:
        if self.api_key:
            return {"headers": {"Authorization": f"ApiKey {self.api_key}"}}
        return {"auth": (self.username, self.password)}

    supports_metrics = True

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        inventory = []
        for key, bucket in self._composite(f"now-{int(self._window_hours())}h",
                                           {"last_seen": {"max": {"field": self.time_field}}}):
            value = (bucket.get("last_seen") or {}).get("value")
            inventory.append({
                "name": str(key.get("name") or ""),
                "identifier": str(key.get("ip") or key.get("name") or ""),
                "last_seen": epoch_to_datetime(value) if value else None,
            })
        return inventory

    def _fetch_metrics(self, window_hours: float) -> List[Dict[str, Any]]:
        """doc_count per host, log types from log_type_field, skew = max(ingested) - max(@timestamp)."""
        sub_aggs = {
            "latest": {"max": {"field": self.time_field}},
            "ingested": {"max": {"field": self.ingest_time_field}},
            "types": {"terms": {"field": self.log_type_field, "size": 50}},
        }
        metrics = []
        for key, bucket in self._composite(f"now-{max(1, int(window_hours * 60))}m", sub_aggs):
            latest = (bucket.get("latest") or {}).get("value")
            ingested = (bucket.get("ingested") or {}).get("value")
            metrics.append({
                "name": str(key.get("name") or ""),
                "identifier": str(key.get("ip") or key.get("name") or ""),
                "events": int(bucket.get("doc_count") or 0),
                "log_types": [b["key"] for b in (bucket.get("types") or {}).get("buckets", []) if "key" in b],
                "max_skew_seconds": abs(ingested - latest) / 1000 if latest and ingested else None,
            })
        return metrics

    def _composite(self, since: str, sub_aggs: Dict[str, Any]):
        """Yield (key, bucket) over every host, paging the composite aggregation."""
        sources = [{"name": {"terms": {"field": self.host_field, "missing_bucket": True}}}]
        if self.ip_field:
            sources.append({"ip": {"terms": {"field": self.ip_field, "missing_bucket": True}}})
        body: Dict[str, Any] = {
            "size": 0,
            "query": {"range": {self.time_field: {"gte": since}}},
            "aggs": {"hosts": {
                "composite": {"size": self.page_size, "sources": sources},
                "aggs": sub_aggs,
            }},
        }
        while True:
            response = self._request("POST", f"{self.base_url}/{self.index}/_search",
                                     json=copy.deepcopy(body), **self._auth())
            agg = (self._json(response, "Elastic").get("aggregations") or {}).get("hosts") or {}
            buckets = agg.get("buckets") or []
            for bucket in buckets:
                yield bucket.get("key") or {}, bucket
            after = agg.get("after_key")
            if not after or len(buckets) < self.page_size:
                return
            body["aggs"]["hosts"]["composite"]["after"] = after
