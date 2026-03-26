"""
fortisiem_client.py
===================
Client for Fortinet FortiSIEM platform.

Environment variables required:
    FORTISIEM_USER  — FortiSIEM username
    FORTISIEM_PASS  — FortiSIEM password

API Reference:
    https://docs.fortinet.com/product/fortisiem (REST API section)

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses.
"""

import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests

from .base_client import BaseSIEMClient


class FortiSIEMClient(BaseSIEMClient):
    """
    Connects to FortiSIEM REST API to retrieve last log event per device.

    Authentication: Basic auth (username:password) or session token.
    Key endpoints:
        POST /phoenix/rest/query/eventQuery  — Run event query for device
        GET  /phoenix/rest/cmdb/devices      — Device lookup
    """

    def __init__(self, config: dict):
        super().__init__(config)
        siem_cfg = config.get("siem", {}).get("fortisiem", {})
        self.base_url = siem_cfg.get(
            "base_url", "https://fortisiem.example.com/phoenix/rest"
        ).rstrip("/")
        self.username = os.environ.get("FORTISIEM_USER", "")
        self.password = os.environ.get("FORTISIEM_PASS", "")

        if (not self.username or not self.password) and not self.mock_mode:
            self.logger.warning(
                "FORTISIEM_USER or FORTISIEM_PASS environment variables not set. "
                "Authentication will fail."
            )

    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Return last log timestamp for a device from FortiSIEM."""
        if self.mock_mode:
            return self._mock_response(device)

        ip = device["ip_address"]
        auth = (self.username, self.password)
        headers = self._build_headers()

        # FortiSIEM uses XML-based query API (simplified here)
        # Real query uses POST with XML payload; this is a representative example
        query_payload = {
            "eventType": "ALL",
            "reportWindow": "Last 3 Days",
            "hostIp": ip,
            "limit": 1,
            "orderBy": "eventTime DESC",
        }

        try:
            # FortiSIEM event search endpoint
            url = f"{self.base_url}/query/eventQuery"
            response = requests.post(
                url,
                json=query_payload,
                auth=auth,
                headers=headers,
                timeout=self.timeout,
                verify=False,  # Override as needed for your deployment
            )
            response.raise_for_status()
            data = response.json()

            # Parse response — adjust to match actual FortiSIEM response schema
            events = data.get("events", []) or data.get("data", [])
            if events:
                raw_ts = events[0].get("eventTime") or events[0].get("receiveTime")
                if raw_ts:
                    # FortiSIEM may return epoch seconds or ISO string
                    if isinstance(raw_ts, (int, float)):
                        return datetime.fromtimestamp(raw_ts, tz=timezone.utc)
                    return datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))

            self.logger.warning(f"FortiSIEM returned no events for {ip}")
            return None

        except requests.exceptions.ConnectionError:
            self.logger.error(f"Cannot connect to FortiSIEM at {self.base_url}")
            raise
        except requests.exceptions.Timeout:
            self.logger.error(f"FortiSIEM API timed out for device {ip}")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(
                f"FortiSIEM HTTP error for {ip}: {e.response.status_code}"
            )
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error querying FortiSIEM for {ip}: {e}")
            raise

    def _mock_response(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Simulate FortiSIEM API response for testing.
        ~75% healthy, 25% stale.
        """
        now = datetime.now(tz=timezone.utc)
        if random.random() < 0.75:
            return now - timedelta(hours=random.uniform(0.2, 23))
        else:
            return now - timedelta(hours=random.uniform(26, 80))
