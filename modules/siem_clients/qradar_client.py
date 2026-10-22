# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
qradar_client.py
================
Client for IBM QRadar SIEM platform.

Environment variables required:
    QRADAR_SEC_TOKEN  — QRadar SEC token (Admin > Authorized Services)

API Reference:
    https://ibmsecuritydocs.github.io/qradar_api_overview/

Lookup modes (config: siem.qradar.lookup):
    log_sources (default)
        Reads every log source once from
        GET /config/event_sources/log_source_management/log_sources
        and uses its `last_event_time`. One paged call covers all devices,
        and the list is cached for `inventory_cache_seconds`.
        A device matches a log source when its ip_address equals the log
        source `identifier`, or its device_name equals the log source
        `name` or `identifier` (case-insensitive).
        The same list powers inventory reconciliation (--reconcile).

    aql
        Runs one Ariel search per device, waits for it to finish, then reads
        the result. The query comes from `aql_template`, which may use
        {ip} and {device_name}.

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses.
"""

import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .base_client import (
    BaseSIEMClient,
    NonRetryableError,
    RetryableError,
    epoch_to_datetime,
    validate_ip,
)

LOG_SOURCES_PATH = "/config/event_sources/log_source_management/log_sources"
DEFAULT_AQL_TEMPLATE = (
    "SELECT MAX(starttime) AS last_seen FROM events "
    "WHERE LOGSOURCENAME(logsourceid) = '{device_name}' LAST 3 DAYS"
)
ARIEL_DONE = "COMPLETED"
ARIEL_FAILED = {"CANCELED", "ERROR"}


def _aql_quote(value: str) -> str:
    """Escape a value for use inside single quotes in AQL."""
    return str(value).replace("\\", "\\\\").replace("'", "''")


class QRadarClient(BaseSIEMClient):
    """Retrieves last log event time per device from the IBM QRadar REST API."""

    config_key = "qradar"
    supports_inventory = True  # Log sources API works in both lookup modes

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = cfg.get("base_url", "https://qradar.example.com/api").rstrip("/")
        self.api_version = str(cfg.get("api_version", "14.0"))
        self.lookup = str(cfg.get("lookup", "log_sources")).lower()
        self.page_size = int(cfg.get("page_size", 500))
        if "log_source_cache_seconds" in cfg:  # Older name for inventory_cache_seconds
            self.inventory_cache_seconds = float(cfg["log_source_cache_seconds"])
        self.aql_template = cfg.get("aql_template", DEFAULT_AQL_TEMPLATE)
        self.poll_interval = float(cfg.get("search_poll_seconds", 2))
        self.search_timeout = float(cfg.get("search_timeout_seconds", 120))
        self.sec_token = self.credential("QRADAR_SEC_TOKEN")

        if self.lookup not in ("log_sources", "aql"):
            raise ValueError(
                f"siem.qradar.lookup must be 'log_sources' or 'aql', got {self.lookup!r}"
            )

    def _headers(self, extra: dict = None) -> dict:
        headers = self._build_headers({"SEC": self.sec_token, "Version": self.api_version})
        if extra:
            headers.update(extra)
        return headers

    # ─── Public API ───────────────────────────────────────────────────────────

    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Return last log timestamp for a device from IBM QRadar."""
        if self.mock_mode:
            return self._mock_response(device)
        if self.lookup == "aql":
            return self._last_seen_aql(device)
        return self._last_seen_log_sources(device)

    # ─── Log source lookup ────────────────────────────────────────────────────

    def _last_seen_log_sources(self, device: Dict[str, Any]) -> Optional[datetime]:
        return self.last_seen_from_inventory(device)

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        inventory = []
        for source in self._fetch_log_sources():
            last = source.get("last_event_time")
            inventory.append({
                "name": source.get("name") or "",
                "identifier": source.get("identifier") or "",
                "last_seen": epoch_to_datetime(last) if isinstance(last, (int, float)) and last > 0 else None,
            })
        return inventory

    def _fetch_log_sources(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}{LOG_SOURCES_PATH}"
        params = {"fields": "id,name,identifier,enabled,last_event_time"}
        sources: List[Dict[str, Any]] = []
        seen_ids = set()
        start = 0
        while True:
            end = start + self.page_size - 1
            response = self._request(
                "GET", url, params=params,
                headers=self._headers({"Range": f"items={start}-{end}"}),
            )
            page = self._json(response, "QRadar")
            if not isinstance(page, list):
                raise NonRetryableError("QRadar log source response is not a list")
            # Stop if the server ignored the Range header and sent everything, or
            # repeats a page we already have — otherwise this would loop forever.
            ids = [s.get("id") for s in page if s.get("id") is not None]
            repeated = bool(ids) and all(i in seen_ids for i in ids)
            if not repeated:
                sources.extend(s for s in page if s.get("id") is None or s.get("id") not in seen_ids)
                seen_ids.update(ids)

            total = self._content_range_total(response.headers.get("Content-Range"))
            if (
                repeated
                or len(page) != self.page_size
                or (total is not None and len(sources) >= total)
            ):
                return sources
            start += self.page_size

    @staticmethod
    def _content_range_total(value: Optional[str]) -> Optional[int]:
        """Parse 'items 0-49/1234' into 1234."""
        if not value or "/" not in value:
            return None
        try:
            return int(value.rsplit("/", 1)[1])
        except ValueError:
            return None

    # ─── AQL lookup ───────────────────────────────────────────────────────────

    def _last_seen_aql(self, device: Dict[str, Any]) -> Optional[datetime]:
        ip = validate_ip(device.get("ip_address", ""))
        aql = self.aql_template.format(
            ip=ip, device_name=_aql_quote(device.get("device_name", ""))
        )

        response = self._request(
            "POST", f"{self.base_url}/ariel/searches",
            params={"query_expression": aql}, headers=self._headers(),
        )
        search_id = self._json(response, "QRadar").get("search_id")
        if not search_id:
            raise NonRetryableError(f"QRadar did not return a search_id for {ip}")

        try:
            self._wait_for_search(search_id)
            response = self._request(
                "GET", f"{self.base_url}/ariel/searches/{search_id}/results",
                headers=self._headers(),
            )
            events = self._json(response, "QRadar").get("events", [])
        finally:
            self._delete_search(search_id)

        last_seen = events[0].get("last_seen") if events else None
        if not last_seen:
            return None
        return epoch_to_datetime(last_seen)

    def _wait_for_search(self, search_id: str):
        """Poll an Ariel search until it completes, fails or times out."""
        deadline = time.monotonic() + self.search_timeout
        while True:
            response = self._request(
                "GET", f"{self.base_url}/ariel/searches/{search_id}",
                headers=self._headers(),
            )
            status = str(self._json(response, "QRadar").get("status", "")).upper()
            if status == ARIEL_DONE:
                return
            if status in ARIEL_FAILED:
                raise NonRetryableError(f"QRadar search {search_id} ended with status {status}")
            if time.monotonic() >= deadline:
                raise RetryableError(
                    f"QRadar search {search_id} not finished after {self.search_timeout:.0f}s"
                )
            time.sleep(self.poll_interval)

    def _delete_search(self, search_id: str):
        """Free the search on the QRadar side. Failures here are only logged."""
        try:
            self._request(
                "DELETE", f"{self.base_url}/ariel/searches/{search_id}",
                headers=self._headers(),
            )
        except Exception as e:
            self.logger.debug(f"Could not delete QRadar search {search_id}: {e}")

    # ─── Mock ─────────────────────────────────────────────────────────────────

    def _mock_response(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Simulate QRadar API response for testing.
        ~65% healthy, 35% stale.
        """
        now = datetime.now(tz=timezone.utc)
        if random.random() < 0.65:
            return now - timedelta(hours=random.uniform(0.1, 22))
        return now - timedelta(hours=random.uniform(25, 96))
