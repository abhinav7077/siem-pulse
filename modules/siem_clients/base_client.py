# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
base_client.py
==============
Abstract base class for all SIEM API clients, plus the shared error types
and HTTP helper every client uses.

Error types tell LogChecker whether a failure is worth retrying:
    RetryableError     — timeouts, connection errors, HTTP 5xx
    RateLimitedError   — HTTP 429 (carries the server's Retry-After, if any)
    NonRetryableError  — bad credentials (401/403), bad request, bad input,
                         unexpected response format. Retrying will not help.
"""

import ipaddress
import logging
import warnings
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Optional, Union

import requests
from urllib3.exceptions import InsecureRequestWarning


# ─── Errors ───────────────────────────────────────────────────────────────────

class SIEMError(Exception):
    """Base class for SIEM client errors."""


class RetryableError(SIEMError):
    """A temporary failure — the request may succeed if retried."""


class RateLimitedError(RetryableError):
    """The SIEM asked us to slow down (HTTP 429)."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class NonRetryableError(SIEMError):
    """A permanent failure — retrying the same request will not help."""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse a Retry-After header (seconds or HTTP date) into seconds."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(tz=timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        return None


def validate_ip(value: str) -> str:
    """Return the normalised IP address, or raise NonRetryableError."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise NonRetryableError(f"Invalid IP address: {value!r}")


def epoch_to_datetime(value: Union[int, float, str]) -> datetime:
    """Convert epoch seconds or milliseconds to an aware UTC datetime."""
    number = float(value)
    if number > 1e11:  # Larger than any epoch-seconds value until year 5138
        number /= 1000.0
    return datetime.fromtimestamp(number, tz=timezone.utc)


# ─── Base client ──────────────────────────────────────────────────────────────

class BaseSIEMClient(ABC):
    """
    Base class for SIEM clients.
    All SIEM implementations must provide get_last_log_time().
    """

    #: Key under config["siem"] holding this client's settings.
    config_key: str = ""

    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        siem_cfg = config.get("siem", {})
        self.timeout = siem_cfg.get("timeout_seconds", 30)
        self.mock_mode = siem_cfg.get("mock_mode", True)
        self.platform_cfg: Dict[str, Any] = siem_cfg.get(self.config_key, {}) or {}

        # verify_ssl: true (default) | false | "/path/to/ca-bundle.pem"
        self.verify_ssl: Union[bool, str] = self.platform_cfg.get("verify_ssl", True)
        if self.verify_ssl is False and not self.mock_mode:
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            self.logger.warning(
                f"TLS certificate verification is DISABLED for {self.config_key}. "
                "Set verify_ssl to true or a CA bundle path in production."
            )

    @abstractmethod
    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Fetch the last log received timestamp for a given device.

        Args:
            device: Dict containing at minimum:
                    - device_name (str)
                    - ip_address  (str)

        Returns:
            datetime of the last log event, or None if the SIEM has no events
            for this device.

        Raises:
            RetryableError / RateLimitedError / NonRetryableError
        """

    def _build_headers(self, extra: dict = None) -> dict:
        """Build common HTTP headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Send an HTTP request and translate failures into SIEM error types.
        Returns the response only for 2xx status codes.
        """
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        name = self.config_key or self.__class__.__name__

        try:
            response = requests.request(method, url, **kwargs)
        except requests.exceptions.Timeout as e:
            raise RetryableError(f"{name} request timed out: {url}") from e
        except requests.exceptions.SSLError as e:
            raise NonRetryableError(f"{name} TLS/SSL error for {url}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise RetryableError(f"Cannot connect to {name} at {url}") from e
        except requests.exceptions.RequestException as e:
            raise RetryableError(f"{name} request failed: {e}") from e

        status = response.status_code
        if 200 <= status < 300:
            return response
        if status == 429:
            raise RateLimitedError(
                f"{name} rate limit hit (HTTP 429)",
                retry_after=parse_retry_after(response.headers.get("Retry-After")),
            )
        if status in (401, 403):
            raise NonRetryableError(
                f"{name} authentication/authorisation failed (HTTP {status}) — check credentials"
            )
        if status >= 500 or status == 408:
            raise RetryableError(f"{name} server error (HTTP {status}) for {url}")
        raise NonRetryableError(f"{name} request rejected (HTTP {status}) for {url}")

    @staticmethod
    def _json(response: requests.Response, name: str) -> Any:
        """Decode a JSON body or raise NonRetryableError."""
        try:
            return response.json()
        except ValueError as e:
            raise NonRetryableError(f"{name} returned a non-JSON response") from e
