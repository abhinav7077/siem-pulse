# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
qradar_client.py
================
Client for IBM QRadar SIEM platform.

Environment variables required:
    QRADAR_SEC_TOKEN  — QRadar SEC token (Settings > Authorized Services)

API Reference:
    https://ibmsecuritydocs.github.io/qradar_api_14.0/

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses.
"""

import os
import random
import warnings
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from .base_client import BaseSIEMClient


class QRadarClient(BaseSIEMClient):
    """
    Connects to IBM QRadar REST API to retrieve last log event per device.

    Authentication: SEC token in header.
    Key endpoint used:
        GET /api/ariel/searches  — Run AQL query to find last event per IP
        GET /api/siem/source_addresses — Asset activity lookup
    """

    def __init__(self, config: dict):
        super().__init__(config)
        siem_cfg = config.get("siem", {}).get("qradar", {})
        self.base_url = siem_cfg.get(
            "base_url", "https://qradar.example.com/api"
        ).rstrip("/")
        self.verify_ssl = siem_cfg.get("verify_ssl", False)
        self.sec_token = os.environ.get("QRADAR_SEC_TOKEN", "")

        if not self.verify_ssl:
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)

        if not self.sec_token and not self.mock_mode:
            self.logger.warning(
                "QRADAR_SEC_TOKEN environment variable is not set. "
                "Requests will likely fail."
            )

    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Return last log timestamp for a device from IBM QRadar."""
        if self.mock_mode:
            return self._mock_response(device)

        ip = device["ip_address"]
        headers = self._build_headers({
            "SEC": self.sec_token,
            "Version": "14.0",
        })

        # QRadar AQL: query last event for this source IP
        # This runs an async search — simplified here to a synchronous poll
        aql = f"SELECT MAX(starttime) AS last_seen FROM events WHERE sourceip='{ip}' LAST 3 DAYS"

        try:
            # Step 1: Submit AQL search
            search_url = f"{self.base_url}/ariel/searches"
            search_resp = requests.post(
                search_url,
                params={"query_expression": aql},
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            search_resp.raise_for_status()
            search_id = search_resp.json().get("search_id")

            if not search_id:
                self.logger.warning(f"QRadar did not return search_id for {ip}")
                return None

            # Step 2: Poll for results (simplified — production should retry with backoff)
            result_url = f"{self.base_url}/ariel/searches/{search_id}/results"
            result_resp = requests.get(
                result_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            result_resp.raise_for_status()
            events = result_resp.json().get("events", [])

            if events and events[0].get("last_seen"):
                # QRadar returns epoch milliseconds
                epoch_ms = events[0]["last_seen"]
                return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)

            self.logger.warning(f"QRadar returned no events for {ip}")
            return None

        except requests.exceptions.ConnectionError:
            self.logger.error(f"Cannot connect to QRadar at {self.base_url}")
            raise
        except requests.exceptions.Timeout:
            self.logger.error(f"QRadar API timed out for device {ip}")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"QRadar HTTP error for {ip}: {e.response.status_code}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error querying QRadar for {ip}: {e}")
            raise

    def _mock_response(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Simulate QRadar API response for testing.
        ~65% healthy, 35% stale.
        """
        now = datetime.now(tz=timezone.utc)
        if random.random() < 0.65:
            return now - timedelta(hours=random.uniform(0.1, 22))
        else:
            return now - timedelta(hours=random.uniform(25, 96))
