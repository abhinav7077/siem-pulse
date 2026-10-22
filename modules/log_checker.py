# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
log_checker.py
==============
Checks whether a device has sent logs within the threshold window.

For each device:
  - Calls the appropriate SIEM client to fetch last log timestamp
  - Compares timestamp against current time
  - Classifies device as: healthy | stale | error
  - Supports configurable retry with exponential backoff
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict

from .siem_clients.base_client import BaseSIEMClient

logger = logging.getLogger(__name__)


class LogChecker:
    """
    Determines log health status for a single device.

    Status values:
        healthy — last log received within threshold_hours
        stale   — last log older than threshold_hours
        error   — could not retrieve timestamp (API error, timeout, etc.)
    """

    def __init__(
        self,
        threshold_hours: int = 24,
        max_retries: int = 3,
        retry_delay: float = 5.0,
    ):
        self.threshold_hours = threshold_hours
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def check_device(
        self, device: Dict[str, Any], client: BaseSIEMClient
    ) -> Dict[str, Any]:
        """
        Check last log time for a device and return a result dict.

        Returns a dict with:
            device_name, ip_address, siem_platform, client_name,
            status, last_log_time, hours_since_last_log, error (if any)
        """
        result = {
            "device_name": device.get("device_name"),
            "ip_address": device.get("ip_address"),
            "siem_platform": device.get("siem_platform"),
            "client_name": device.get("client_name", "N/A"),
            "notes": device.get("notes", ""),
            "status": "error",
            "last_log_time": None,
            "hours_since_last_log": None,
            "error": None,
            "checked_at": datetime.now(tz=timezone.utc).isoformat(),
        }

        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                last_log_time = client.get_last_log_time(device)

                if last_log_time is None:
                    # API succeeded but no events found — treat as stale
                    result["status"] = "stale"
                    result["last_log_time"] = "Never / Not Found"
                    result["hours_since_last_log"] = float("inf")
                    return result

                # Ensure timezone-aware for comparison
                now = datetime.now(tz=timezone.utc)
                if last_log_time.tzinfo is None:
                    last_log_time = last_log_time.replace(tzinfo=timezone.utc)

                hours_since = (now - last_log_time).total_seconds() / 3600
                result["last_log_time"] = last_log_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                result["hours_since_last_log"] = round(hours_since, 2)
                result["status"] = (
                    "healthy" if hours_since <= self.threshold_hours else "stale"
                )
                return result

            except Exception as e:
                last_error = e
                if attempt < self.max_retries:
                    wait = self.retry_delay * (2 ** (attempt - 1))  # Exponential backoff
                    logger.warning(
                        f"Attempt {attempt}/{self.max_retries} failed for "
                        f"{device.get('device_name')} — retrying in {wait:.1f}s: {e}"
                    )
                    time.sleep(wait)
                else:
                    logger.error(
                        f"All {self.max_retries} attempts failed for "
                        f"{device.get('device_name')}: {e}"
                    )

        result["status"] = "error"
        result["error"] = str(last_error)
        return result
