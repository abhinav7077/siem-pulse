# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
seceon_client.py
================
Client for Seceon OTM (Open Threat Management) SIEM platform.

Environment variables required:
    SECEON_API_KEY  — API key for authentication

API Docs reference:
    https://seceon-tenant.seceon.com/api/v2/docs (replace with your tenant URL)

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses
    without connecting to a real Seceon instance (useful for testing/demo).
"""

import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests

from .base_client import BaseSIEMClient


class SeceonClient(BaseSIEMClient):
    """
    Connects to Seceon OTM API to retrieve device log activity.

    Authentication: API Key in Authorization header.
    Endpoint: /api/v2/devices/{ip}/lastlog  (mock endpoint — adjust to real API)
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = (
            config.get("siem", {})
            .get("seceon", {})
            .get("base_url", "https://seceon.example.com/api/v2")
        ).rstrip("/")
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

        ip = device["ip_address"]
        url = f"{self.base_url}/devices/{ip}/lastlog"
        headers = self._build_headers({"Authorization": f"Bearer {self.api_key}"})

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            # Adapt this parsing to match real Seceon API response schema
            # Example assumed response: { "last_event_time": "2024-01-15T10:30:00Z" }
            raw_ts = data.get("last_event_time") or data.get("lastEventTime")
            if raw_ts:
                return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))

            self.logger.warning(f"Seceon returned no timestamp for {ip}: {data}")
            return None

        except requests.exceptions.ConnectionError:
            self.logger.error(f"Cannot connect to Seceon at {url}")
            raise
        except requests.exceptions.Timeout:
            self.logger.error(f"Seceon API timed out for device {ip}")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"Seceon HTTP error for {ip}: {e.response.status_code}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error querying Seceon for {ip}: {e}")
            raise

    def _mock_response(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Simulate Seceon API response for testing.
        ~70% of devices are healthy, 30% are stale.
        """
        now = datetime.now(tz=timezone.utc)
        if random.random() < 0.70:
            # Healthy: log received 1–20 hours ago
            return now - timedelta(hours=random.uniform(0.5, 20))
        else:
            # Stale: log received 25–72 hours ago
            return now - timedelta(hours=random.uniform(25, 72))
