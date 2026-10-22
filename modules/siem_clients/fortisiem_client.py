# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
fortisiem_client.py
===================
Client for Fortinet FortiSIEM platform.

Environment variables required:
    FORTISIEM_USER  — FortiSIEM username. On multi-tenant (service provider)
                      deployments use the "<organization>/<user>" form,
                      e.g. "super/admin".
    FORTISIEM_PASS  — FortiSIEM password

API Reference:
    https://docs.fortinet.com/product/fortisiem (Integration API guide)

Query flow (FortiSIEM event query API):
    1. POST {base_url}/query/eventQuery         XML query  -> query id
    2. GET  {base_url}/query/progress/{id}      repeat until it reports 100
    3. GET  {base_url}/query/events/{id}/0/1    XML result -> newest event

`base_url` should end in /phoenix/rest.

Lookup modes (config: siem.fortisiem.lookup):
    per_device (default) — one query per device, filtered on reptDevIpAddr.
    grouped              — one query per tenant that groups all events by
                           reporting device and takes MAX(phRecvTime). Much
                           faster for large inventories, and enables
                           inventory reconciliation (--reconcile).

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses.
"""

import random
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from .base_client import (
    BaseSIEMClient,
    NonRetryableError,
    RetryableError,
    epoch_to_datetime,
    validate_ip,
)

#: Event attributes checked for the receive time, in order of preference.
TIME_ATTRIBUTES = ("phRecvTime", "receiveTime", "eventTime")

QUERY_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Reports>
  <Report baseline="" rsSync="">
    <Name>{name}</Name>
    <Description>SIEM Pulse last-log check</Description>
    <CustomerScope groupByEachCustomer="true">
      <Include all="true"/>
      <Exclude/>
    </CustomerScope>
    <SelectClause>
      <AttrList>phRecvTime,reptDevIpAddr,eventType</AttrList>
    </SelectClause>
    <OrderByClause>
      <AttrList>phRecvTime DESC</AttrList>
    </OrderByClause>
    <PatternClause>
      <SubPattern id="1" name="Filter">
        <SingleEvtConstr>reptDevIpAddr = {ip}</SingleEvtConstr>
      </SubPattern>
    </PatternClause>
    <ReportInterval>
      <Low>{low}</Low>
      <High>{high}</High>
    </ReportInterval>
  </Report>
</Reports>
"""


GROUPED_QUERY_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<Reports>
  <Report baseline="" rsSync="">
    <Name>SIEM Pulse - last log per device</Name>
    <Description>SIEM Pulse grouped last-log check</Description>
    <CustomerScope groupByEachCustomer="true">
      <Include all="true"/>
      <Exclude/>
    </CustomerScope>
    <SelectClause>
      <AttrList>reptDevIpAddr,reptDevName,MAX(phRecvTime)</AttrList>
    </SelectClause>
    <GroupByClause>
      <AttrList>reptDevIpAddr,reptDevName</AttrList>
    </GroupByClause>
    <ReportInterval>
      <Low>{low}</Low>
      <High>{high}</High>
    </ReportInterval>
  </Report>
</Reports>
"""


def parse_fortisiem_time(value: str) -> datetime:
    """
    Parse the time formats FortiSIEM returns: epoch seconds/milliseconds,
    ISO 8601, or Java-style text such as "Tue Oct 21 10:00:00 UTC 2026".
    """
    text = str(value).strip()
    if text.replace(".", "", 1).isdigit():
        return epoch_to_datetime(text)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y", "%m/%d/%Y %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        raise NonRetryableError(f"Unrecognised FortiSIEM time format: {text!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class FortiSIEMClient(BaseSIEMClient):
    """Retrieves last log event time per device from the FortiSIEM REST API."""

    config_key = "fortisiem"
    inventory_lookup_mode = "grouped"

    def __init__(self, config: dict, base_url: Optional[str] = None, auth_ref: Optional[str] = None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        cfg = self.platform_cfg
        self.base_url = cfg.get(
            "base_url", "https://fortisiem.example.com/phoenix/rest"
        ).rstrip("/")
        self.window_hours = float(cfg.get("query_window_hours", 72))
        self.poll_interval = float(cfg.get("query_poll_seconds", 2))
        self.query_timeout = float(cfg.get("query_timeout_seconds", 120))
        self.lookup = str(cfg.get("lookup", "per_device")).lower()
        if self.lookup not in ("per_device", "grouped"):
            raise ValueError(
                f"siem.fortisiem.lookup must be 'per_device' or 'grouped', got {self.lookup!r}"
            )
        self.supports_inventory = self.lookup == "grouped"
        self.page_size = int(cfg.get("page_size", 1000))
        self.username = self.credential("FORTISIEM_USER")
        self.password = self.credential("FORTISIEM_PASS")

    def _call(self, method: str, path: str, **kwargs):
        kwargs.setdefault("auth", (self.username, self.password))
        return self._request(method, f"{self.base_url}{path}", **kwargs)

    # ─── Public API ───────────────────────────────────────────────────────────

    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Return last log timestamp for a device from FortiSIEM."""
        if self.mock_mode:
            return self._mock_response(device)
        if self.lookup == "grouped":
            return self.last_seen_from_inventory(device)

        ip = validate_ip(device.get("ip_address", ""))
        query_id = self._submit_query(ip, device.get("device_name", ""))
        self._wait_for_query(query_id)

        response = self._call(
            "GET", f"/query/events/{query_id}/0/1", headers={"Accept": "application/xml"}
        )
        return self._parse_events(response.text, ip)

    # ─── Steps ────────────────────────────────────────────────────────────────

    def _window(self):
        high = int(time.time())
        return high - int(self.window_hours * 3600), high

    def _submit_query(self, ip: str, device_name: str) -> str:
        low, high = self._window()
        body = QUERY_TEMPLATE.format(
            name=escape(f"SIEM Pulse - {device_name or ip}"), ip=ip, low=low, high=high
        )
        return self._post_query(body, ip)

    def _post_query(self, body: str, label: str) -> str:
        response = self._call(
            "POST", "/query/eventQuery",
            data=body.encode("utf-8"),
            headers={"Content-Type": "text/xml", "Accept": "text/plain, application/xml"},
        )
        query_id = response.text.strip()
        if not query_id or query_id.startswith("<") or " " in query_id:
            raise NonRetryableError(f"FortiSIEM did not return a query id for {label}: {query_id[:200]!r}")
        return query_id

    def _wait_for_query(self, query_id: str):
        """Poll query progress until it reaches 100%."""
        deadline = time.monotonic() + self.query_timeout
        while True:
            response = self._call("GET", f"/query/progress/{query_id}")
            progress_text = response.text.strip().split(",")[0]
            try:
                progress = int(float(progress_text))
            except ValueError:
                raise NonRetryableError(
                    f"Unexpected FortiSIEM progress response for query {query_id}: "
                    f"{response.text[:200]!r}"
                )
            if progress >= 100:
                return
            if time.monotonic() >= deadline:
                raise RetryableError(
                    f"FortiSIEM query {query_id} not finished after {self.query_timeout:.0f}s"
                )
            time.sleep(self.poll_interval)

    @staticmethod
    def _parse_xml(xml_text: str, label: str) -> ET.Element:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            raise NonRetryableError(f"FortiSIEM returned invalid XML for {label}: {e}")
        error = root.find(".//error")
        if error is not None:
            description = error.find("description")
            message = (
                (description.text if description is not None else None)
                or error.text or error.get("description") or ""
            ).strip()
            raise NonRetryableError(f"FortiSIEM query error for {label}: {message or 'unknown'}")
        return root

    @staticmethod
    def _event_values(event: ET.Element) -> Dict[str, str]:
        values = {
            attr.get("name"): (attr.text or "").strip()
            for attr in event.iter("attribute")
        }
        for child in event:  # Some versions put times in child elements
            if child.tag in TIME_ATTRIBUTES and (child.text or "").strip():
                values.setdefault(child.tag, child.text.strip())
        return values

    @staticmethod
    def _event_time(values: Dict[str, str]) -> Optional[datetime]:
        for key in TIME_ATTRIBUTES:
            if values.get(key):
                return parse_fortisiem_time(values[key])
        for key, value in values.items():  # e.g. "MAX(phRecvTime)" in grouped results
            if key and "recvtime" in key.lower() and value:
                return parse_fortisiem_time(value)
        return None

    def _parse_events(self, xml_text: str, ip: str) -> Optional[datetime]:
        root = self._parse_xml(xml_text, ip)
        event = root.find(".//event")
        if event is None:
            self.logger.warning(f"FortiSIEM returned no events for {ip}")
            return None
        when = self._event_time(self._event_values(event))
        if when is None:
            raise NonRetryableError(f"FortiSIEM event for {ip} has no receive time attribute")
        return when

    # ─── Grouped (bulk) lookup ────────────────────────────────────────────────

    def _fetch_inventory(self) -> List[Dict[str, Any]]:
        low, high = self._window()
        query_id = self._post_query(GROUPED_QUERY_TEMPLATE.format(low=low, high=high), "grouped query")
        self._wait_for_query(query_id)

        by_device: Dict[tuple, Dict[str, Any]] = {}
        start = 0
        while True:
            response = self._call(
                "GET", f"/query/events/{query_id}/{start}/{start + self.page_size}",
                headers={"Accept": "application/xml"},
            )
            events = self._parse_xml(response.text, "grouped query").findall(".//event")
            for event in events:
                values = self._event_values(event)
                key = (values.get("reptDevIpAddr", ""), values.get("reptDevName", ""))
                when = self._event_time(values)
                current = by_device.get(key)
                if current is None or (when and (not current["last_seen"] or when > current["last_seen"])):
                    by_device[key] = {"identifier": key[0], "name": key[1], "last_seen": when}
            if len(events) < self.page_size:
                return list(by_device.values())
            start += self.page_size

    # ─── Mock ─────────────────────────────────────────────────────────────────

    def _mock_response(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Simulate FortiSIEM API response for testing.
        ~75% healthy, 25% stale.
        """
        now = datetime.now(tz=timezone.utc)
        if random.random() < 0.75:
            return now - timedelta(hours=random.uniform(0.2, 23))
        return now - timedelta(hours=random.uniform(26, 80))
