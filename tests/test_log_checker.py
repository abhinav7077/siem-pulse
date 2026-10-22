# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
from datetime import datetime, timedelta, timezone

from siem_pulse import log_checker
from siem_pulse.log_checker import LogChecker
from siem_pulse.siem_clients.base_client import (
    NonRetryableError,
    RateLimitedError,
    RetryableError,
)

DEVICE = {"device_name": "fw", "ip_address": "10.0.0.1", "siem_platform": "qradar"}


class ScriptedClient:
    """Raises or returns the scripted values in order."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def get_last_log_time(self, device):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def no_sleep(monkeypatch):
    sleeps = []
    monkeypatch.setattr(log_checker.time, "sleep", sleeps.append)
    return sleeps


def test_non_retryable_error_is_not_retried(monkeypatch):
    sleeps = no_sleep(monkeypatch)
    client = ScriptedClient(NonRetryableError("HTTP 401"))
    result = LogChecker(max_retries=3).check_device(DEVICE, client)
    assert client.calls == 1 and sleeps == []
    assert result["status"] == "error" and "401" in result["error"]


def test_retryable_error_retries_with_backoff(monkeypatch):
    sleeps = no_sleep(monkeypatch)
    recent = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    client = ScriptedClient(RetryableError("timeout"), RetryableError("timeout"), recent)
    result = LogChecker(max_retries=3, retry_delay=5).check_device(DEVICE, client)
    assert result["status"] == "healthy"
    assert sleeps == [5, 10]


def test_rate_limit_honours_retry_after_with_cap(monkeypatch):
    sleeps = no_sleep(monkeypatch)
    recent = datetime.now(tz=timezone.utc)
    client = ScriptedClient(RateLimitedError("429", retry_after=60), RateLimitedError("429", retry_after=9999), recent)
    LogChecker(max_retries=3, retry_delay=1, max_retry_after=120).check_device(DEVICE, client)
    assert sleeps == [60, 120]


def test_never_seen_is_stale_with_empty_hours():
    result = LogChecker().check_device(DEVICE, ScriptedClient(None))
    assert result["status"] == "stale"
    assert result["hours_since_last_log"] is None


def test_threshold():
    old = datetime.now(tz=timezone.utc) - timedelta(hours=30)
    assert LogChecker(threshold_hours=24).check_device(DEVICE, ScriptedClient(old))["status"] == "stale"
