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

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses
    without connecting to a real Seceon instance (useful for testing/demo).
"""

import os
import random
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
        raise NonRetryableError(f"Unrecognised Seceon timestamp: {value!r}")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class SeceonClient(BaseSIEMClient):
    """Retrieves last log event time per device from the Seceon API."""

    config_key = "seceon"

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = self.platform_cfg
        self.base_url = cfg.get("base_url", "https://seceon.example.com/api/v2").rstrip("/")
        self.path_template = cfg.get("last_log_path", DEFAULT_PATH)
        fields = cfg.get("timestamp_fields", DEFAULT_FIELDS)
        self.timestamp_fields: List[str] = [fields] if isinstance(fields, str) else list(fields)
        self.auth_header = cfg.get("auth_header", "Authorization")
        self.auth_scheme = cfg.get("auth_scheme", "Bearer")
        self.api_key = os.environ.get("SECEON_API_KEY", "")
        if not self.api_key and not self.mock_mode:
            self.logger.warning(
                "SECEON_API_KEY environment variable is not set. "
                "Requests will likely fail."
            )

    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Return last log timestamp for a device from Seceon."""
        if self.mock_mode:
            return self._mock_response(device)

        ip = validate_ip(device.get("ip_address", ""))
        path = self.path_template.format(
            ip=quote(ip, safe=""),
            device_name=quote(str(device.get("device_name", "")), safe=""),
        )
        token = f"{self.auth_scheme} {self.api_key}".strip()
        headers = self._build_headers({self.auth_header: token})

        response = self._request("GET", f"{self.base_url}{path}", headers=headers)
        data = self._json(response, "Seceon")
        if not isinstance(data, dict):
            raise NonRetryableError(
                f"Seceon response for {ip} is not a JSON object — check last_log_path"
            )

        for field in self.timestamp_fields:
            value = _lookup(data, field)
            if value not in (None, ""):
                return _to_datetime(value)

        # A valid response with none of the fields: either the device has no
        # events, or timestamp_fields does not match this Seceon version.
        self.logger.warning(
            f"Seceon response for {ip} has none of {self.timestamp_fields}. "
            f"Top-level keys: {sorted(data.keys())[:10]}"
        )
        return None

    def _mock_response(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Simulate Seceon API response for testing.
        ~70% of devices are healthy, 30% are stale.
        """
        now = datetime.now(tz=timezone.utc)
        if random.random() < 0.70:
            return now - timedelta(hours=random.uniform(0.5, 20))
        return now - timedelta(hours=random.uniform(25, 72))
