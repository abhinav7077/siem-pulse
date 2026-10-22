# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
inventory_sources.py
====================
Where the device inventory comes from.

config.yaml:

    devices:
      source: file              # file (default: .xlsx / .csv / .yaml) | servicenow
      file: sample_devices.xlsx
      sheet_name: Devices

ServiceNow CMDB:

    devices:
      source: servicenow
      servicenow:
        instance_url: "https://acme.service-now.com"
        table: cmdb_ci                  # e.g. cmdb_ci_netgear, cmdb_ci_server
        query: "operational_status=1^u_siem_platformISNOTEMPTY"   # sysparm_query
        page_size: 1000
        verify_ssl: true
        field_map:                      # inventory column -> ServiceNow field
          device_name: name
          ip_address: ip_address
          siem_platform: u_siem_platform
          client_name: company
          criticality: u_criticality
        defaults:                       # used when a field is empty
          siem_platform: qradar

Credentials: SERVICENOW_USER / SERVICENOW_PASS (through the configured
secrets provider). Reference fields such as `company` are read as display
values (sysparm_display_value=true), so you get "Acme Corp", not a sys_id.
"""

import logging
from typing import Any, Dict, List

import requests

from .credentials import get_secret
from .excel_reader import ExcelReader

logger = logging.getLogger(__name__)

DEFAULT_FIELD_MAP = {
    "device_name": "name",
    "ip_address": "ip_address",
    "siem_platform": "u_siem_platform",
    "client_name": "company",
}


def _display(value: Any) -> Any:
    """ServiceNow may return {'display_value': ..., 'value': ...} for references."""
    if isinstance(value, dict):
        return value.get("display_value") or value.get("value")
    return value


class ServiceNowInventory:
    def __init__(self, config: dict):
        self.config = config
        cfg = config.get("devices", {}).get("servicenow", {}) or {}
        self.instance_url = str(cfg.get("instance_url", "")).rstrip("/")
        if not self.instance_url:
            raise ValueError("devices.servicenow.instance_url is required")
        self.table = cfg.get("table", "cmdb_ci")
        self.query = cfg.get("query", "")
        self.page_size = int(cfg.get("page_size", 1000))
        self.verify = cfg.get("verify_ssl", True)
        self.timeout = cfg.get("timeout_seconds", 30)
        self.field_map: Dict[str, str] = {**DEFAULT_FIELD_MAP, **(cfg.get("field_map") or {})}
        self.defaults: Dict[str, Any] = cfg.get("defaults") or {}

    def fetch_records(self) -> List[Dict[str, Any]]:
        user = get_secret(self.config, "SERVICENOW_USER")
        password = get_secret(self.config, "SERVICENOW_PASS")
        if not user or not password:
            raise ValueError("SERVICENOW_USER and SERVICENOW_PASS must be set")

        url = f"{self.instance_url}/api/now/table/{self.table}"
        fields = sorted(set(self.field_map.values()))
        records: List[Dict[str, Any]] = []
        offset = 0
        while True:
            params = {
                "sysparm_fields": ",".join(fields),
                "sysparm_limit": self.page_size,
                "sysparm_offset": offset,
                "sysparm_display_value": "true",
                "sysparm_exclude_reference_link": "true",
            }
            if self.query:
                params["sysparm_query"] = self.query
            try:
                response = requests.get(
                    url, params=params, auth=(user, password), timeout=self.timeout,
                    verify=self.verify, headers={"Accept": "application/json"},
                )
            except requests.exceptions.RequestException as e:
                raise ValueError(f"Cannot reach ServiceNow at {self.instance_url}: {e}") from e
            if response.status_code != 200:
                raise ValueError(f"ServiceNow returned HTTP {response.status_code} for {url}")
            page = response.json().get("result", [])
            records.extend(page)
            if len(page) < self.page_size:
                break
            offset += self.page_size
        logger.info(f"Fetched {len(records)} CIs from ServiceNow table {self.table}")
        return records

    def to_devices(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows = []
        for record in records:
            row = {}
            for column, field in self.field_map.items():
                value = _display(record.get(field))
                row[column] = value if value not in (None, "") else self.defaults.get(column)
            for column, value in self.defaults.items():
                row.setdefault(column, value)
            rows.append(row)
        return ExcelReader.from_records(rows, source=f"ServiceNow {self.table}")

    def load_devices(self) -> List[Dict[str, Any]]:
        return self.to_devices(self.fetch_records())


def load_inventory(config: dict, device_file: str, sheet_name: str = "Devices") -> List[Dict[str, Any]]:
    """Load devices from the configured source."""
    source = str(config.get("devices", {}).get("source", "file")).lower()
    if source == "servicenow":
        return ServiceNowInventory(config).load_devices()
    if source != "file":
        raise ValueError(f"Unknown devices.source '{source}' (use file or servicenow)")
    return ExcelReader(device_file, sheet_name=sheet_name).load_devices()
