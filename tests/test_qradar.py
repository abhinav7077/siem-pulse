# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
from datetime import datetime, timezone

import pytest

from modules.siem_clients.base_client import NonRetryableError
from modules.siem_clients.qradar_client import QRadarClient
from tests.conftest import FakeResponse

MS = 1_760_000_000_000  # epoch milliseconds
EXPECTED = datetime.fromtimestamp(MS / 1000, tz=timezone.utc)

LOG_SOURCES = "/log_source_management/log_sources"


def log_source_pages(http):
    http.add("GET", LOG_SOURCES, [
        FakeResponse(200, [
            {"id": 1, "name": "FW @ 10.0.0.1", "identifier": "10.0.0.1", "last_event_time": MS},
            {"id": 2, "name": "dc01", "identifier": "dc01.corp.local", "last_event_time": MS - 1000},
        ], headers={"Content-Range": "items 0-1/3"}),
        FakeResponse(200, [
            {"id": 3, "name": "new-box", "identifier": "10.0.0.9", "last_event_time": 0},
        ], headers={"Content-Range": "items 2-2/3"}),
    ])


def test_log_sources_match_by_ip_and_name_with_paging(http, config):
    log_source_pages(http)
    client = QRadarClient(config)

    assert client.get_last_log_time({"device_name": "fw", "ip_address": "10.0.0.1"}) == EXPECTED
    assert client.get_last_log_time({"device_name": "DC01", "ip_address": "10.9.9.9"}) is not None
    # Paged once (2 requests) and then served from cache
    assert http.count("GET", LOG_SOURCES) == 2
    first = http.calls[0]
    assert first["headers"]["Range"] == "items=0-1"
    assert first["headers"]["SEC"] == ""
    assert http.calls[1]["headers"]["Range"] == "items=2-3"


def test_log_source_never_seen_or_missing_returns_none(http, config):
    log_source_pages(http)
    client = QRadarClient(config)
    assert client.get_last_log_time({"device_name": "x", "ip_address": "10.0.0.9"}) is None
    assert client.get_last_log_time({"device_name": "ghost", "ip_address": "10.1.1.1"}) is None


def aql_config(config):
    config["siem"]["qradar"]["lookup"] = "aql"
    return config


def test_aql_waits_for_completion_then_reads_and_deletes(http, config):
    http.add("POST", "/ariel/searches", FakeResponse(201, {"search_id": "abc"}))
    http.add("GET", "/ariel/searches/abc/results", FakeResponse(200, {"events": [{"last_seen": MS}]}))
    http.add("GET", "/ariel/searches/abc", [
        FakeResponse(200, {"status": "WAIT"}),
        FakeResponse(200, {"status": "EXECUTE"}),
        FakeResponse(200, {"status": "COMPLETED"}),
    ])
    http.add("DELETE", "/ariel/searches/abc", FakeResponse(202, {}))

    client = QRadarClient(aql_config(config))
    result = client.get_last_log_time({"device_name": "o'brien-fw", "ip_address": "10.0.0.1"})

    assert result == EXPECTED
    status_polls = [c for c in http.calls if c["method"] == "GET" and c["url"].endswith("/abc")]
    assert len(status_polls) == 3
    assert http.count("DELETE", "/ariel/searches/abc") == 1
    query = http.calls[0]["params"]["query_expression"]
    assert "'o''brien-fw'" in query  # single quote escaped for AQL


def test_aql_failed_search_is_not_retryable(http, config):
    http.add("POST", "/ariel/searches", FakeResponse(201, {"search_id": "abc"}))
    http.add("GET", "/ariel/searches/abc", FakeResponse(200, {"status": "ERROR"}))
    http.add("DELETE", "/ariel/searches/abc", FakeResponse(202, {}))
    with pytest.raises(NonRetryableError):
        QRadarClient(aql_config(config)).get_last_log_time(
            {"device_name": "fw", "ip_address": "10.0.0.1"}
        )


def test_aql_rejects_bad_ip_before_calling_api(http, config):
    with pytest.raises(NonRetryableError):
        QRadarClient(aql_config(config)).get_last_log_time(
            {"device_name": "fw", "ip_address": "1.1.1.1' OR 1=1"}
        )
    assert http.calls == []


def test_aql_no_events_returns_none(http, config):
    http.add("POST", "/ariel/searches", FakeResponse(201, {"search_id": "abc"}))
    http.add("GET", "/ariel/searches/abc/results", FakeResponse(200, {"events": [{"last_seen": None}]}))
    http.add("GET", "/ariel/searches/abc", FakeResponse(200, {"status": "COMPLETED"}))
    http.add("DELETE", "/ariel/searches/abc", FakeResponse(202, {}))
    assert QRadarClient(aql_config(config)).get_last_log_time(
        {"device_name": "fw", "ip_address": "10.0.0.1"}
    ) is None
