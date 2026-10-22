# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
from datetime import datetime, timezone

import pytest

from siem_pulse.siem_clients.base_client import NonRetryableError
from siem_pulse.siem_clients.seceon_client import SeceonClient
from tests.conftest import FakeResponse

DEVICE = {"device_name": "web-01", "ip_address": "10.10.1.10"}


def test_default_endpoint_and_auth(http, config, monkeypatch):
    monkeypatch.setenv("SECEON_API_KEY", "k3y")
    http.add("GET", "/devices/10.10.1.10/lastlog",
             FakeResponse(200, {"last_event_time": "2025-10-09T08:53:20Z"}))
    result = SeceonClient(config).get_last_log_time(DEVICE)
    assert result == datetime(2025, 10, 9, 8, 53, 20, tzinfo=timezone.utc)
    assert http.calls[0]["headers"]["Authorization"] == "Bearer k3y"


def test_configurable_path_and_nested_epoch_field(http, config):
    config["siem"]["seceon"].update({
        "last_log_path": "/assets/{device_name}/status",
        "timestamp_fields": ["data.last_seen"],
    })
    http.add("GET", "/assets/web-01/status", FakeResponse(200, {"data": {"last_seen": 1760000000000}}))
    assert SeceonClient(config).get_last_log_time(DEVICE) == datetime.fromtimestamp(
        1_760_000_000, tz=timezone.utc
    )


def test_missing_field_returns_none(http, config):
    http.add("GET", "/lastlog", FakeResponse(200, {"something_else": 1}))
    assert SeceonClient(config).get_last_log_time(DEVICE) is None


def test_non_object_response_is_not_retryable(http, config):
    http.add("GET", "/lastlog", FakeResponse(200, ["unexpected"]))
    with pytest.raises(NonRetryableError):
        SeceonClient(config).get_last_log_time(DEVICE)
