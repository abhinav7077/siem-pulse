# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
from datetime import datetime, timezone

import pytest

from siem_pulse.siem_clients.base_client import NonRetryableError
from siem_pulse.siem_clients.fortisiem_client import FortiSIEMClient, parse_fortisiem_time
from tests.conftest import FakeResponse

DEVICE = {"device_name": "fw-01", "ip_address": "172.16.5.1"}


def events_xml(time_value):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<queryResult><events><event id="1" index="0"><attributes>
  <attribute name="phRecvTime">{time_value}</attribute>
  <attribute name="reptDevIpAddr">172.16.5.1</attribute>
</attributes></event></events></queryResult>"""


def setup_query(http, result_xml):
    http.add("POST", "/query/eventQuery", FakeResponse(200, text="12345,1760000000000"))
    http.add("GET", "/query/progress/", [FakeResponse(200, text="40"), FakeResponse(200, text="100")])
    http.add("GET", "/query/events/12345,1760000000000/0/1", FakeResponse(200, text=result_xml))


def test_full_query_flow(http, config):
    setup_query(http, events_xml("1760000000000"))
    result = FortiSIEMClient(config).get_last_log_time(DEVICE)

    assert result == datetime.fromtimestamp(1_760_000_000, tz=timezone.utc)
    submit = http.calls[0]
    assert submit["headers"]["Content-Type"] == "text/xml"
    body = submit["data"].decode()
    assert "reptDevIpAddr = 172.16.5.1" in body
    assert "<Low>" in body and "<High>" in body
    assert http.count("GET", "/query/progress/") == 2
    assert submit["verify"] is True  # no longer hardcoded to False


def test_no_events_returns_none(http, config):
    setup_query(http, "<queryResult><events></events></queryResult>")
    assert FortiSIEMClient(config).get_last_log_time(DEVICE) is None


def test_error_response_is_not_retryable(http, config):
    setup_query(http, '<response><error code="255"><description>bad</description></error></response>')
    with pytest.raises(NonRetryableError):
        FortiSIEMClient(config).get_last_log_time(DEVICE)


def test_invalid_ip_rejected(http, config):
    with pytest.raises(NonRetryableError):
        FortiSIEMClient(config).get_last_log_time({"device_name": "x", "ip_address": "fw.local"})
    assert http.calls == []


@pytest.mark.parametrize("value", [
    "1760000000", "1760000000000", "2025-10-09T08:53:20Z", "Thu Oct 09 08:53:20 UTC 2025",
])
def test_time_formats(value):
    assert parse_fortisiem_time(value) == datetime(2025, 10, 9, 8, 53, 20, tzinfo=timezone.utc)
