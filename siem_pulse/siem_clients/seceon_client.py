# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
seceon_client.py
================
Client for Seceon aiSIEM / OTM platform.

Environment variables required:
    SECEON_API_KEY  — API key for authentication

Seceon's API is documented per tenant (it is not publicly published), so the
endpoint and response fields are configurable rather than hardcoded:

    siem:
      seceon:
        base_url: "https://<tenant>.seceon.com/api/v2"
        last_log_path: "/devices/{ip}/lastlog"     # {ip} and {device_name} allowed
        timestamp_fields: ["last_event_time", "lastEventTime"]
        auth_header: "Authorization"
        auth_scheme: "Bearer"                       # "" to send the key alone

`timestamp_fields` entries may use dots for nested fields, e.g. "data.last_seen".
Timestamps may be ISO 8601 strings or epoch seconds/milliseconds.

Bulk mode (optional): if your tenant has an endpoint that lists all devices
with their last event time, set lookup: bulk and describe it:

        lookup: bulk
        bulk_path: "/devices"                 # returns a list, or an object holding one
        bulk_items_field: "items"             # where the list is ("" if the body is the list)
        bulk_ip_field: "ip"
        bulk_name_field: "name"

Bulk mode makes one call per tenant and enables inventory reconciliation.

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses
    without connecting to a real Seceon instance (useful for testing/demo).
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .base_client import (
    BaseSIEMClient,
    NonRetryableError,
    epoch_to_datetime,
    validate_ip,
)

DEFAULT_PATH = "/devices/{ip}/lastlog"
DEFAULT_FIELDS = ["last_event_time", "lastEventTime"]


def _lookup(data: Any, dotted: str) -> Any:
    """Read a possibly nested field like 'data.last_seen'."""
    for part in dotted.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        return epoch_to_datetime(value)
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        raise NonRetryableError(f"Unrecognised Seceon timestamp: {value!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class SeceonClient(BaseSIEMClient):
    """Retrieves last log event time per device from the Seceon API."""

    config_key = "seceon"
    inventory_lookup_mode = "bulk"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = cfg.get("base_url", "https://seceon.example.com/api/v2").rstrip("/")
        self.path_template = cfg.get("last_log_path", DEFAULT_PATH)
        fields = cfg.get("timestamp_fields", DEFAULT_FIELDS)
        self.timestamp_fields: List[str] = [fields] if isinstance(fields, str) else list(fields)
        self.auth_header = cfg.get("auth_header", "Authorization")
        self.auth_scheme = cfg.get("auth_scheme", "Bearer")
        self.lookup = str(cfg.get("lookup", "per_device")).lower()
        if self.lookup not in ("per_device", "bulk"):
            raise ValueError(f"siem.seceon.lookup must be 'per_device' or 'bulk', got {self.lookup!r}")
        self.supports_inventory = self.lookup == "bulk"
        self.bulk_path = cfg.get("bulk_path", "/devices")
        self.bulk_items_field = cfg.get("bulk_items_field", "items")
        self.bulk_ip_field = cfg.get("bulk_ip_field", "ip")
        self.bulk_name_field = cfg.get("bulk_name_field", "name")
        self.api_key = self.credential("SECEON_API_KEY")

    def _auth_headers(self) -> dict:
        token = f"{self.auth_scheme} {self.api_key}".strip()
        return self._build_headers({self.auth_header: token})

    def _timestamp(self, item: Dict[str, Any]) -> Optional[datetime]:
        for field in self.timestamp_fields:
            value = _lookup(item, field)
            if value not in (None, ""):
                return _to_datetime(value)
        return None

    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Return last log timestamp for a device from Seceon."""
        if self.mock_mode:
            return self._mock_response(device)
        if self.lookup == "bulk":
            return self.last_seen_from_inventory(device)

        ip = validate_ip(device.get("ip_address", ""))
        path = self.path_template.format(
            ip=quote(ip, safe=""),
            device_name=quote(str(device.get("device_name", "")), safe=""),
        )
        response = self._request("GET", f"{self.base_url}{path}", headers=self._auth_headers())
        data = self._json(response, "Seceon")
        if not isinstance(data, dict):
            raise NonRetryableError(
                f"Seceon response for {ip} is not a JSON object — check last_log_path"
            )

        when = self._timestamp(data)
        if when is not None:
            return when

        # A valid response with none of the fields: either the device has no
        # events, or timestamp_fields does not match this Seceon version.
        self.logger.warning(
            f"Seceon response for {ip} has none of {self.timestamp_fields}. "
            f"Top-level keys: {sorted(data.keys())[:10]}"
        )
        return None

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        response = self._request("GET", f"{self.base_url}{self.bulk_path}", headers=self._auth_headers())
        data = self._json(response, "Seceon")
        items = _lookup(data, self.bulk_items_field) if self.bulk_items_field else data
        if not isinstance(items, list):
            raise NonRetryableError(
                f"Seceon bulk response has no list at '{self.bulk_items_field}' — check bulk_items_field"
            )
        return [
            {
                "identifier": str(_lookup(item, self.bulk_ip_field) or ""),
                "name": str(_lookup(item, self.bulk_name_field) or ""),
                "last_seen": self._timestamp(item),
            }
            for item in items if isinstance(item, dict)
        ]

    def _mock_response(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Simulate Seceon API response for testing.
        ~70% of devices are healthy, 30% are stale.
        """
        now = datetime.now(tz=timezone.utc)
        rng = self._mock_rng(device)
        if rng.random() < 0.70:
            return now - timedelta(hours=rng.uniform(0.5, 20))
        return now - timedelta(hours=rng.uniform(25, 72))
