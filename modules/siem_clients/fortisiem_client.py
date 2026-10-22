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

Mock mode:
    Set `siem.mock_mode: true` in config.yaml to return simulated responses.
"""

import os
import random
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
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

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = self.platform_cfg
        self.base_url = cfg.get(
            "base_url", "https://fortisiem.example.com/phoenix/rest"
        ).rstrip("/")
        self.window_hours = float(cfg.get("query_window_hours", 72))
        self.poll_interval = float(cfg.get("query_poll_seconds", 2))
        self.query_timeout = float(cfg.get("query_timeout_seconds", 120))
        self.username = os.environ.get("FORTISIEM_USER", "")
        self.password = os.environ.get("FORTISIEM_PASS", "")

        if (not self.username or not self.password) and not self.mock_mode:
            self.logger.warning(
                "FORTISIEM_USER or FORTISIEM_PASS environment variables not set. "
                "Authentication will fail."
            )

    def _call(self, method: str, path: str, **kwargs):
        kwargs.setdefault("auth", (self.username, self.password))
        return self._request(method, f"{self.base_url}{path}", **kwargs)

    # ─── Public API ───────────────────────────────────────────────────────────

    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """Return last log timestamp for a device from FortiSIEM."""
        if self.mock_mode:
            return self._mock_response(device)

        ip = validate_ip(device.get("ip_address", ""))
        query_id = self._submit_query(ip, device.get("device_name", ""))
        self._wait_for_query(query_id)

        response = self._call(
            "GET", f"/query/events/{query_id}/0/1", headers={"Accept": "application/xml"}
        )
        return self._parse_events(response.text, ip)

    # ─── Steps ────────────────────────────────────────────────────────────────

    def _submit_query(self, ip: str, device_name: str) -> str:
        high = int(time.time())
        low = high - int(self.window_hours * 3600)
        body = QUERY_TEMPLATE.format(
            name=escape(f"SIEM Pulse - {device_name or ip}"), ip=ip, low=low, high=high
        )
        response = self._call(
            "POST", "/query/eventQuery",
            data=body.encode("utf-8"),
            headers={"Content-Type": "text/xml", "Accept": "text/plain, application/xml"},
        )
        query_id = response.text.strip()
        if not query_id or query_id.startswith("<") or " " in query_id:
            raise NonRetryableError(f"FortiSIEM did not return a query id for {ip}: {query_id[:200]!r}")
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

    def _parse_events(self, xml_text: str, ip: str) -> Optional[datetime]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            raise NonRetryableError(f"FortiSIEM returned invalid XML for {ip}: {e}")

        error = root.find(".//error")
        if error is not None:
            message = (error.text or error.get("description") or "").strip()
            raise NonRetryableError(f"FortiSIEM query error for {ip}: {message or 'unknown'}")

        event = root.find(".//event")
        if event is None:
            self.logger.warning(f"FortiSIEM returned no events for {ip}")
            return None

        values = {
            attr.get("name"): (attr.text or "").strip()
            for attr in event.iter("attribute")
        }
        for child in event:  # Some versions put times in child elements
            if child.tag in TIME_ATTRIBUTES and (child.text or "").strip():
                values.setdefault(child.tag, child.text.strip())

        for key in TIME_ATTRIBUTES:
            if values.get(key):
                return parse_fortisiem_time(values[key])
        raise NonRetryableError(f"FortiSIEM event for {ip} has no receive time attribute")

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
