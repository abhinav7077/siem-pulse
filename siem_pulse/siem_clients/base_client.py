# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
base_client.py
==============
Abstract base class for all SIEM API clients, plus the shared error types,
HTTP helper, per-tenant settings and credentials, rate limiting and the
bulk "known sources" cache every client can use.

Error types tell LogChecker whether a failure is worth retrying:
    RetryableError     — timeouts, connection errors, HTTP 5xx
    RateLimitedError   — HTTP 429 (carries the server's Retry-After, if any)
    NonRetryableError  — bad credentials (401/403), bad request, bad input,
                         unexpected response format. Retrying will not help.

Tenants (multi-client setups):
    A client instance serves one (platform, api_endpoint, auth_ref) tenant.
    - api_endpoint (inventory column) overrides the platform base_url.
    - auth_ref (inventory column) selects:
        * settings overrides from siem.<platform>.tenants.<auth_ref> in config
        * credentials from env vars prefixed with the auth_ref, e.g.
          auth_ref "acme" + QRADAR_SEC_TOKEN  ->  ACME_QRADAR_SEC_TOKEN
      A tenant never falls back to the default (unprefixed) credentials, so one
      client's credentials are never sent to another client's SIEM.
"""

import ipaddress
import logging
import random
import threading
import time
import warnings
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Union

import requests
from urllib3.exceptions import InsecureRequestWarning

from ..credentials import SecretError, env_prefix, get_resolver  # noqa: F401  (env_prefix re-exported)


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
        raise NonRetryableError(f"Invalid IP address: {value!r}") from None


def epoch_to_datetime(value: Union[int, float, str]) -> datetime:
    """Convert epoch seconds or milliseconds to an aware UTC datetime."""
    number = float(value)
    if number > 1e11:  # Larger than any epoch-seconds value until year 5138
        number /= 1000.0
    return datetime.fromtimestamp(number, tz=timezone.utc)




class RateLimiter:
    """Thread-safe limiter: at most `rate` requests per second (0 = unlimited)."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.interval
        if start > now:
            time.sleep(start - now)


# ─── Base client ──────────────────────────────────────────────────────────────

class BaseSIEMClient(ABC):
    """
    Base class for SIEM clients.
    All SIEM implementations must provide get_last_log_time().

    Clients that can list every source the SIEM knows about in one go set
    `supports_inventory = True` (when the configured mode allows it) and
    implement `_fetch_inventory()`. That enables bulk per-device lookups and
    inventory reconciliation.
    """

    #: Key under config["siem"] holding this client's settings.
    config_key: str = ""

    def __init__(
        self,
        config: dict,
        base_url: Optional[str] = None,
        auth_ref: Optional[str] = None,
    ):
        self.config = config
        self.auth_ref = auth_ref or None
        self.logger = logging.getLogger(
            self.__class__.__name__ + (f"[{self.auth_ref}]" if self.auth_ref else "")
        )
        siem_cfg = config.get("siem", {})
        self.timeout = siem_cfg.get("timeout_seconds", 30)
        self.mock_mode = siem_cfg.get("mock_mode", True)
        self.mock_seed = siem_cfg.get("mock_seed")

        # Platform settings, then tenant overrides, then the inventory endpoint
        platform_cfg = dict(siem_cfg.get(self.config_key, {}) or {})
        tenants = platform_cfg.pop("tenants", {}) or {}
        if self.auth_ref:
            tenant_cfg = tenants.get(self.auth_ref) or tenants.get(str(self.auth_ref).lower())
            platform_cfg.update(tenant_cfg or {})
        if base_url:
            platform_cfg["base_url"] = base_url
        self.platform_cfg: Dict[str, Any] = platform_cfg

        # verify_ssl: true (default) | false | "/path/to/ca-bundle.pem"
        self.verify_ssl: Union[bool, str] = self.platform_cfg.get("verify_ssl", True)
        if self.verify_ssl is False and not self.mock_mode:
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            self.logger.warning(
                f"TLS certificate verification is DISABLED for {self.config_key}. "
                "Set verify_ssl to true or a CA bundle path in production."
            )

        # Concurrency and rate limits apply per tenant (per client instance)
        max_concurrent = int(self.platform_cfg.get("max_concurrent_requests", 0) or 0)
        self._semaphore = threading.BoundedSemaphore(max_concurrent) if max_concurrent > 0 else None
        self._rate_limiter = RateLimiter(float(self.platform_cfg.get("requests_per_second", 0) or 0))
        self._sessions = threading.local()

        # Bulk inventory cache
        self.inventory_cache_seconds = float(self.platform_cfg.get("inventory_cache_seconds", 300))
        self._inventory_lock = threading.Lock()
        self._inventory: Optional[List[Dict[str, Any]]] = None
        self._inventory_time = 0.0
        self._inventory_error: Optional[NonRetryableError] = None

        self._missing_credentials: List[str] = []

    def _mock_rng(self, device: Dict[str, Any]):
        """
        Random source for mock responses. With siem.mock_seed set, each device
        gets the same simulated result on every run (repeatable demos/tests).
        """
        if self.mock_seed is None:
            return random
        key = f"{self.mock_seed}|{self.config_key}|{device.get('device_name')}|{device.get('ip_address')}"
        return random.Random(key)

    @property
    def tenant_label(self) -> str:
        return f"{self.config_key}" + (f" [{self.auth_ref}]" if self.auth_ref else "")

    # ─── Credentials ──────────────────────────────────────────────────────────

    def credential(self, name: str) -> str:
        """
        Read a credential from the configured secrets provider (default: env).
        With an auth_ref, only that tenant's secret is used (never the default).
        Missing values are remembered and reported when a request is made.
        """
        if self.mock_mode:
            return ""
        resolver = get_resolver(self.config)
        where = resolver.describe(name, self.auth_ref)
        try:
            value = resolver.get(name, self.auth_ref) or ""
        except SecretError as e:
            self._missing_credentials.append(f"{where} ({e})")
            self.logger.error(f"Cannot read {where}: {e}")
            return ""
        if not value:
            self._missing_credentials.append(where)
            self.logger.warning(f"Credential not set: {where}")
        return value

    def _require_credentials(self):
        """Refuse to call a tenant's API without that tenant's credentials."""
        if self.auth_ref and self._missing_credentials:
            raise NonRetryableError(
                f"Missing credentials for auth_ref '{self.auth_ref}': "
                f"set {', '.join(self._missing_credentials)}"
            )

    # ─── Device lookup ────────────────────────────────────────────────────────

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

    # ─── Bulk inventory ───────────────────────────────────────────────────────

    supports_inventory: bool = False

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        """
        Return every source the SIEM knows, as dicts with:
            name (str), identifier (str), last_seen (datetime | None)
        Override in clients that support it.
        """
        raise NotImplementedError

    def list_known_sources(self) -> List[Dict[str, Any]]:
        """All sources the SIEM knows about, fetched at most once per cache window."""
        if not self.supports_inventory:
            raise NonRetryableError(f"{self.tenant_label} does not support listing sources")
        with self._inventory_lock:
            fresh = time.monotonic() - self._inventory_time < self.inventory_cache_seconds
            if fresh and self._inventory_error is not None:
                # A permanent failure (e.g. bad token) is not retried per device
                raise self._inventory_error
            if self._inventory is None or not fresh:
                try:
                    inventory = self._mock_inventory() if self.mock_mode else self._fetch_inventory()
                except NonRetryableError as e:
                    self._inventory, self._inventory_error = None, e
                    self._inventory_time = time.monotonic()
                    raise
                self._inventory, self._inventory_error = inventory, None
                self._inventory_time = time.monotonic()
                self.logger.info(f"Loaded {len(inventory)} sources from {self.tenant_label}")
            return self._inventory

    def _mock_inventory(self) -> List[Dict[str, Any]]:
        """Demo data for mock mode: two sources that are not in any inventory."""
        now = datetime.now(tz=timezone.utc)
        tag = env_prefix(self.auth_ref).lower().strip("_") or "default"
        return [
            {"name": f"unlisted-{self.config_key}-{tag}-{i}",
             "identifier": f"192.0.2.{i}", "last_seen": now}
            for i in (1, 2)
        ]

    @staticmethod
    def source_matches(device: Dict[str, Any], source: Dict[str, Any]) -> bool:
        """
        A device matches a source when its IP equals the source identifier,
        or its name equals the source name or identifier (case-insensitive).
        """
        ip = str(device.get("ip_address") or "").strip().lower()
        name = str(device.get("device_name") or "").strip().lower()
        identifier = str(source.get("identifier") or "").strip().lower()
        source_name = str(source.get("name") or "").strip().lower()
        return bool((ip and identifier == ip) or (name and name in (identifier, source_name)))

    def last_seen_from_inventory(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Look a device up in the bulk inventory; newest time across all matches."""
        matches = [s for s in self.list_known_sources() if self.source_matches(device, s)]
        if not matches:
            self.logger.warning(
                f"No {self.tenant_label} source matches {device.get('device_name')} "
                f"({device.get('ip_address')})"
            )
            return None
        times = [s["last_seen"] for s in matches if s.get("last_seen")]
        return max(times) if times else None

    # ─── HTTP ─────────────────────────────────────────────────────────────────

    def _build_headers(self, extra: dict = None) -> dict:
        """Build common HTTP headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    def _session(self) -> requests.Session:
        """One pooled HTTP session per thread (requests.Session is not thread-safe)."""
        session = getattr(self._sessions, "session", None)
        if session is None:
            session = requests.Session()
            self._sessions.session = session
        return session

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Send an HTTP request and translate failures into SIEM error types.
        Returns the response only for 2xx status codes.
        """
        self._require_credentials()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        name = self.tenant_label

        self._rate_limiter.wait()
        if self._semaphore:
            self._semaphore.acquire()
        try:
            response = self._session().request(method, url, **kwargs)
        except requests.exceptions.Timeout as e:
            raise RetryableError(f"{name} request timed out: {url}") from e
        except requests.exceptions.SSLError as e:
            raise NonRetryableError(f"{name} TLS/SSL error for {url}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise RetryableError(f"Cannot connect to {name} at {url}") from e
        except requests.exceptions.RequestException as e:
            raise RetryableError(f"{name} request failed: {e}") from e
        finally:
            if self._semaphore:
                self._semaphore.release()

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
