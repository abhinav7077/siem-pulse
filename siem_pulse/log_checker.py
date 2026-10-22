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
  - Retries only temporary failures (timeouts, connection errors, HTTP 5xx
    and 429) with exponential backoff; honours the SIEM's Retry-After header
  - Fails fast on permanent errors (bad credentials, bad input)
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .siem_clients.base_client import BaseSIEMClient, NonRetryableError, RateLimitedError

logger = logging.getLogger(__name__)


def device_key(device: Dict[str, Any]) -> str:
    """Stable identity of a device across runs (platform, tenant, client, name, IP)."""
    parts = [
        device.get("siem_platform"), device.get("api_endpoint"), device.get("auth_ref"),
        device.get("client_name"), device.get("device_name"), device.get("ip_address"),
    ]
    return "|".join(str(p or "").strip().lower() for p in parts)


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
        threshold_hours: float = 24,
        max_retries: int = 3,
        retry_delay: float = 5.0,
        max_retry_after: float = 300.0,
        criticality_thresholds: Optional[Dict[str, float]] = None,
    ):
        self.threshold_hours = threshold_hours
        self.criticality_thresholds = {
            str(k).lower(): float(v) for k, v in (criticality_thresholds or {}).items()
        }
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_retry_after = max_retry_after

    def threshold_for(self, device: Dict[str, Any]) -> float:
        """Device threshold_hours, else the threshold for its criticality, else the global one."""
        if device.get("threshold_hours"):
            return float(device["threshold_hours"])
        criticality = str(device.get("criticality") or "").lower()
        if criticality in self.criticality_thresholds:
            return self.criticality_thresholds[criticality]
        return float(self.threshold_hours)

    def check_device(
        self, device: Dict[str, Any], client: BaseSIEMClient
    ) -> Dict[str, Any]:
        """
        Check last log time for a device and return a result dict.

        Returns a dict with:
            device_name, ip_address, siem_platform, client_name,
            status, last_log_time, hours_since_last_log, error (if any)
        """
        threshold = self.threshold_for(device)
        result = {
            **device,
            "device_key": device_key(device),
            "client_name": device.get("client_name") or "N/A",
            "notes": device.get("notes") or "",
            "criticality": device.get("criticality") or "medium",
            "threshold_hours": threshold,
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
                    result["hours_since_last_log"] = None
                    return result

                # Ensure timezone-aware for comparison
                now = datetime.now(tz=timezone.utc)
                if last_log_time.tzinfo is None:
                    last_log_time = last_log_time.replace(tzinfo=timezone.utc)

                hours_since = (now - last_log_time).total_seconds() / 3600
                result["last_log_time"] = last_log_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                result["hours_since_last_log"] = round(hours_since, 2)
                result["status"] = (
                    "healthy" if hours_since <= threshold else "stale"
                )
                return result

            except NonRetryableError as e:
                logger.error(f"{device.get('device_name')}: {e} (not retrying)")
                last_error = e
                break

            except Exception as e:
                last_error = e
                if attempt >= self.max_retries:
                    logger.error(
                        f"All {self.max_retries} attempts failed for "
                        f"{device.get('device_name')}: {e}"
                    )
                    break
                wait = self.retry_delay * (2 ** (attempt - 1))  # Exponential backoff
                if isinstance(e, RateLimitedError) and e.retry_after is not None:
                    wait = max(wait, min(e.retry_after, self.max_retry_after))
                logger.warning(
                    f"Attempt {attempt}/{self.max_retries} failed for "
                    f"{device.get('device_name')} — retrying in {wait:.1f}s: {e}"
                )
                time.sleep(wait)

        result["status"] = "error"
        result["error"] = str(last_error)
        return result
