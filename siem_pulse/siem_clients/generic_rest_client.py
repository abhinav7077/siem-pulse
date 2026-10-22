# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
generic_rest_client.py
======================
A configurable connector for any SIEM or log platform with a REST endpoint
that lists sources and their last event time. Use it for platforms without a
dedicated connector (e.g. LogRhythm, Google SecOps, ArcSight, Graylog, a CMDB
export) — set siem_platform: generic_rest in the inventory.

    siem:
      generic_rest:
        base_url: "https://siem.example.com"
        path: "/api/log-sources"
        method: GET                       # or POST with `body`
        body: {}                          # JSON body for POST
        params: {}                        # extra query parameters
        items_field: "data.items"         # where the list is ("" if the body is the list)
        ip_field: "ip"
        name_field: "name"
        time_field: "lastEventTime"       # ISO 8601 or epoch seconds/ms; dots for nested
        auth: header                      # header | basic | none
        auth_header: "Authorization"
        auth_scheme: "Bearer"             # "" to send the token alone
        # token secret GENERIC_REST_TOKEN; basic auth uses GENERIC_REST_USER / GENERIC_REST_PASS
        pagination: none                  # none | offset | page
        offset_param: offset
        limit_param: limit
        page_param: page
        page_size: 500

Use tenants: (keyed by auth_ref) to point different clients at different
platforms, each with its own field mapping.
"""

from typing import Any, Dict, List, Optional

from .base_client import InventoryClient, NonRetryableError, dig, parse_timestamp


class GenericRestClient(InventoryClient):
    config_key = "generic_rest"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = str(cfg.get("base_url", "")).rstrip("/")
        self.path = cfg.get("path", "/")
        self.method = str(cfg.get("method", "GET")).upper()
        self.body = cfg.get("body")
        self.params = dict(cfg.get("params") or {})
        self.items_field = cfg.get("items_field", "")
        self.ip_field = cfg.get("ip_field", "ip")
        self.name_field = cfg.get("name_field", "name")
        self.time_field = cfg.get("time_field", "last_seen")
        self.auth = str(cfg.get("auth", "header")).lower()
        self.pagination = str(cfg.get("pagination", "none")).lower()
        self.page_size = int(cfg.get("page_size", 500))
        self.max_pages = int(cfg.get("max_pages", 1000))
        self.token = self.credential("GENERIC_REST_TOKEN") if self.auth == "header" else ""
        if self.auth == "basic":
            self.username = self.credential("GENERIC_REST_USER")
            self.password = self.credential("GENERIC_REST_PASS")

    def _auth_kwargs(self) -> Dict[str, Any]:
        if self.auth == "header":
            value = f"{self.platform_cfg.get('auth_scheme', 'Bearer')} {self.token}".strip()
            return {"headers": {self.platform_cfg.get("auth_header", "Authorization"): value,
                                "Accept": "application/json"}}
        if self.auth == "basic":
            return {"auth": (self.username, self.password), "headers": {"Accept": "application/json"}}
        return {"headers": {"Accept": "application/json"}}

    def _page_params(self, page: int) -> Dict[str, Any]:
        cfg = self.platform_cfg
        if self.pagination == "offset":
            return {cfg.get("offset_param", "offset"): page * self.page_size,
                    cfg.get("limit_param", "limit"): self.page_size}
        if self.pagination == "page":
            return {cfg.get("page_param", "page"): page + int(cfg.get("first_page", 1)),
                    cfg.get("limit_param", "limit"): self.page_size}
        return {}

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        if not self.base_url:
            raise NonRetryableError("siem.generic_rest.base_url is required")
        inventory: List[Dict[str, Any]] = []
        for page in range(self.max_pages):
            kwargs = self._auth_kwargs()
            kwargs["params"] = {**self.params, **self._page_params(page)}
            if self.method != "GET" and self.body is not None:
                kwargs["json"] = self.body
            data = self._json(self._request(self.method, f"{self.base_url}{self.path}", **kwargs), "generic_rest")
            items = dig(data, self.items_field)
            if not isinstance(items, list):
                raise NonRetryableError(
                    f"generic_rest: no list at items_field '{self.items_field}' — check the field mapping"
                )
            for item in items:
                if isinstance(item, dict):
                    inventory.append({
                        "identifier": str(dig(item, self.ip_field) or ""),
                        "name": str(dig(item, self.name_field) or ""),
                        "last_seen": parse_timestamp(dig(item, self.time_field)),
                    })
            if self.pagination == "none" or len(items) < self.page_size:
                return inventory
        return inventory
