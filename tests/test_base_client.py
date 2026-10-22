# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
import pytest
import requests

from modules.siem_clients.base_client import (
    NonRetryableError,
    RateLimitedError,
    RetryableError,
    epoch_to_datetime,
    parse_retry_after,
    validate_ip,
)
from modules.siem_clients.qradar_client import QRadarClient
from tests.conftest import FakeResponse


@pytest.mark.parametrize(
    "status, error",
    [(401, NonRetryableError), (403, NonRetryableError), (404, NonRetryableError),
     (400, NonRetryableError), (500, RetryableError), (503, RetryableError)],
)
def test_status_codes_map_to_error_types(http, config, status, error):
    http.add("GET", "/x", FakeResponse(status, {}))
    with pytest.raises(error):
        QRadarClient(config)._request("GET", "https://qradar.test/api/x")


def test_429_carries_retry_after(http, config):
    http.add("GET", "/x", FakeResponse(429, {}, headers={"Retry-After": "12"}))
    with pytest.raises(RateLimitedError) as info:
        QRadarClient(config)._request("GET", "https://qradar.test/api/x")
    assert info.value.retry_after == 12


def test_timeout_is_retryable(monkeypatch, config):
    def boom(*a, **k):
        raise requests.exceptions.Timeout()
    monkeypatch.setattr(requests, "request", boom)
    with pytest.raises(RetryableError):
        QRadarClient(config)._request("GET", "https://qradar.test/api/x")


def test_verify_ssl_is_passed_through(http, config):
    config["siem"]["qradar"]["verify_ssl"] = "/etc/ca.pem"
    http.add("GET", "/x", FakeResponse(200, {}))
    QRadarClient(config)._request("GET", "https://qradar.test/api/x")
    assert http.calls[0]["verify"] == "/etc/ca.pem"


def test_parse_retry_after():
    assert parse_retry_after("5") == 5
    assert parse_retry_after(None) is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0  # date in the past
    assert parse_retry_after("soon") is None


def test_validate_ip():
    assert validate_ip(" 10.0.0.1 ") == "10.0.0.1"
    with pytest.raises(NonRetryableError):
        validate_ip("10.0.0.1' OR '1'='1")


def test_epoch_seconds_and_milliseconds_agree():
    assert epoch_to_datetime(1_700_000_000) == epoch_to_datetime(1_700_000_000_000)
