# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Phase 5: Splunk, Sentinel, Elastic, Wazuh, Sumo Logic, generic REST, plugins."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from siem_pulse.siem_clients import factory
from siem_pulse.siem_clients.base_client import BaseSIEMClient, NonRetryableError, parse_timestamp
from siem_pulse.siem_clients.elastic_client import ElasticClient
from siem_pulse.siem_clients.generic_rest_client import GenericRestClient
from siem_pulse.siem_clients.sentinel_client import SentinelClient
from siem_pulse.siem_clients.splunk_client import SplunkClient
from siem_pulse.siem_clients.sumologic_client import SumoLogicClient
from siem_pulse.siem_clients.wazuh_client import WazuhClient
from tests.conftest import FakeResponse

T = datetime(2025, 10, 9, 8, 53, 20, tzinfo=timezone.utc)
EPOCH = int(T.timestamp())
FW = {"device_name": "fw-01", "ip_address": "10.0.0.1"}
DC = {"device_name": "DC01", "ip_address": "10.0.0.5"}


def cfg(platform, **settings):
    return {"siem": {"mock_mode": False, platform: settings}}


def test_parse_timestamp_shapes():
    assert parse_timestamp(EPOCH) == T
    assert parse_timestamp(str(EPOCH * 1000)) == T
    assert parse_timestamp("2025-10-09T08:53:20Z") == T
    assert parse_timestamp("") is None and parse_timestamp(0) is None
    with pytest.raises(NonRetryableError):
        parse_timestamp("yesterday")


def test_splunk_export_search(http, monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    lines = [
        {"preview": False, "result": {"host": "10.0.0.1", "last_seen": str(EPOCH)}},
        {"preview": False, "result": {"host": "dc01", "last_seen": str(EPOCH - 60)}},
        {"preview": False, "lastrow": True},
    ]
    http.add("POST", "/services/search/jobs/export",
             FakeResponse(200, text="\n".join(json.dumps(x) for x in lines)))
    client = SplunkClient(cfg("splunk", base_url="https://splunk.test:8089", lookback_hours=48))
    assert client.get_last_log_time(FW) == T
    assert client.get_last_log_time(DC) is not None
    call = http.calls[0]
    assert call["headers"]["Authorization"] == "Bearer tok"
    assert "earliest=-48h" in call["data"]["search"] and call["data"]["output_mode"] == "json"
    assert http.count("POST", "/export") == 1


def test_splunk_basic_auth_and_errors(http, monkeypatch):
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.setenv("SPLUNK_USER", "u")
    monkeypatch.setenv("SPLUNK_PASS", "p")
    http.add("POST", "/export", FakeResponse(200, text=json.dumps(
        {"messages": [{"type": "FATAL", "text": "Unknown search command"}]})))
    client = SplunkClient(cfg("splunk", base_url="https://splunk.test:8089"))
    with pytest.raises(NonRetryableError, match="Unknown search command"):
        client.get_last_log_time(FW)
    assert http.calls[0]["auth"] == ("u", "p")


def test_sentinel_token_and_query(http, monkeypatch):
    monkeypatch.setenv("SENTINEL_CLIENT_ID", "cid")
    monkeypatch.setenv("SENTINEL_CLIENT_SECRET", "sec")
    http.add("POST", "login.test/tenant-1/oauth2/v2.0/token",
             FakeResponse(200, {"access_token": "jwt", "expires_in": 3600}))
    http.add("POST", "/v1/workspaces/ws-1/query", FakeResponse(200, {"tables": [{
        "columns": [{"name": "Name"}, {"name": "Ip"}, {"name": "LastSeen"}],
        "rows": [["FW-01", "10.0.0.1", "2025-10-09T08:53:20Z"], ["dc01", "", "2025-10-09T08:00:00Z"]],
    }]}))
    client = SentinelClient(cfg("sentinel", workspace_id="ws-1", tenant_id="tenant-1",
                                login_url="https://login.test", base_url="https://la.test"))
    assert client.get_last_log_time(FW) == T
    assert client.get_last_log_time(DC) is not None
    token_call, query_call = http.calls
    assert token_call["data"]["scope"] == "https://la.test/.default"
    assert query_call["headers"]["Authorization"] == "Bearer jwt"
    assert query_call["json"]["timespan"] == "PT72H"


def test_sentinel_missing_columns(http, monkeypatch):
    http.add("POST", "/token", FakeResponse(200, {"access_token": "jwt"}))
    http.add("POST", "/query", FakeResponse(200, {"tables": [{"columns": [{"name": "x"}], "rows": []}]}))
    client = SentinelClient(cfg("sentinel", workspace_id="w", tenant_id="t"))
    with pytest.raises(NonRetryableError, match="missing columns"):
        client.list_known_sources()


def test_elastic_composite_paging(http, monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "a2V5")
    pages = [
        FakeResponse(200, {"aggregations": {"hosts": {
            "after_key": {"name": "fw-01", "ip": "10.0.0.1"},
            "buckets": [{"key": {"name": "fw-01", "ip": "10.0.0.1"}, "last_seen": {"value": EPOCH * 1000}}]}}}),
        FakeResponse(200, {"aggregations": {"hosts": {"buckets": []}}}),
    ]
    http.add("POST", "/logs-*/_search", pages)
    client = ElasticClient(cfg("elastic", base_url="https://es.test:9200", page_size=1))
    assert client.get_last_log_time(FW) == T
    first, second = http.calls
    assert first["headers"]["Authorization"] == "ApiKey a2V5"
    assert "after" not in first["json"]["aggs"]["hosts"]["composite"]
    assert second["json"]["aggs"]["hosts"]["composite"]["after"] == {"name": "fw-01", "ip": "10.0.0.1"}


def test_wazuh_agents(http, monkeypatch):
    monkeypatch.setenv("WAZUH_USER", "api")
    monkeypatch.setenv("WAZUH_PASS", "pw")
    http.add("POST", "/security/user/authenticate", FakeResponse(200, {"data": {"token": "jwt"}}))
    http.add("GET", "/agents", [
        FakeResponse(200, {"data": {"total_affected_items": 3, "affected_items": [
            {"id": "000", "name": "manager", "ip": "127.0.0.1", "lastKeepAlive": "9999-12-31T23:59:59+00:00"},
            {"id": "001", "name": "fw-01", "ip": "10.0.0.1", "lastKeepAlive": "2025-10-09T08:53:20+00:00"}]}}),
        FakeResponse(200, {"data": {"total_affected_items": 3, "affected_items": [
            {"id": "002", "name": "dc01", "ip": "10.0.0.5", "lastKeepAlive": "2025-10-09T08:00:00+00:00"}]}}),
    ])
    client = WazuhClient(cfg("wazuh", base_url="https://wazuh.test:55000", page_size=2))
    assert client.get_last_log_time(FW) == T
    names = [s["name"] for s in client.list_known_sources()]
    assert names == ["fw-01", "dc01"]                 # manager skipped, both pages read
    assert http.calls[0]["auth"] == ("api", "pw")
    assert http.calls[1]["headers"]["Authorization"] == "Bearer jwt"
    assert http.calls[2]["params"]["offset"] == 2


def test_sumologic_search_job(http, monkeypatch):
    monkeypatch.setenv("SUMO_ACCESS_ID", "id")
    monkeypatch.setenv("SUMO_ACCESS_KEY", "key")
    http.add("POST", "/v1/search/jobs", FakeResponse(202, {"id": "J1"}))
    http.add("GET", "/v1/search/jobs/J1/records", FakeResponse(200, {"records": [
        {"map": {"_sourcehost": "10.0.0.1", "last_seen": str(EPOCH * 1000)}}]}))
    http.add("GET", "/v1/search/jobs/J1", [
        FakeResponse(200, {"state": "GATHERING RESULTS"}),
        FakeResponse(200, {"state": "DONE GATHERING RESULTS", "recordCount": 1}),
    ])
    http.add("DELETE", "/v1/search/jobs/J1", FakeResponse(200, {}))
    client = SumoLogicClient(cfg("sumologic", base_url="https://api.sumo.test/api", search_poll_seconds=0))
    assert client.get_last_log_time(FW) == T
    assert http.calls[0]["json"]["byReceiptTime"] is True
    assert http.count("DELETE", "/J1") == 1


def test_generic_rest_offset_paging_and_nested_fields(http, monkeypatch):
    monkeypatch.setenv("GENERIC_REST_TOKEN", "t")
    http.add("GET", "/api/sources", [
        FakeResponse(200, {"data": {"items": [
            {"host": {"ip": "10.0.0.1", "name": "fw-01"}, "stats": {"last": "2025-10-09T08:53:20Z"}},
            {"host": {"ip": "10.0.0.2", "name": "sw-01"}, "stats": {"last": None}}]}}),
        FakeResponse(200, {"data": {"items": []}}),
    ])
    client = GenericRestClient(cfg(
        "generic_rest", base_url="https://siem.test", path="/api/sources", items_field="data.items",
        ip_field="host.ip", name_field="host.name", time_field="stats.last",
        pagination="offset", page_size=2, auth_scheme="Token"))
    assert client.get_last_log_time(FW) == T
    assert client.get_last_log_time({"device_name": "sw-01", "ip_address": "1.1.1.1"}) is None
    assert http.calls[0]["headers"]["Authorization"] == "Token t"
    assert [c["params"]["offset"] for c in http.calls] == [0, 2]


def test_generic_rest_bad_mapping(http):
    http.add("GET", "/x", FakeResponse(200, {"rows": []}))
    client = GenericRestClient(cfg("generic_rest", base_url="https://siem.test", path="/x",
                                   items_field="data", auth="none"))
    with pytest.raises(NonRetryableError, match="items_field"):
        client.list_known_sources()


def test_new_connectors_registered_and_mock_mode():
    for name in ("splunk", "sentinel", "elastic", "wazuh", "sumologic", "generic_rest"):
        assert name in factory.SIEM_REGISTRY
        client = factory.SIEM_REGISTRY[name]({"siem": {"mock_mode": True, "mock_seed": 3}})
        assert client.get_last_log_time(FW) is not None


def test_connector_plugins_load(monkeypatch):
    class GraylogClient(BaseSIEMClient):
        config_key = "graylog"

        def get_last_log_time(self, device):
            return T

    eps = [SimpleNamespace(name="Graylog", value="pkg:GraylogClient", load=lambda: GraylogClient),
           SimpleNamespace(name="broken", value="pkg:Nope", load=lambda: object)]
    monkeypatch.setattr(factory, "entry_points", lambda group: eps if group == "siem_pulse.connectors" else [])
    monkeypatch.setattr(factory, "_plugins_loaded", False)
    monkeypatch.setitem(factory.SIEM_REGISTRY, "placeholder", None)  # ensures cleanup of the dict
    try:
        assert "graylog" in factory.SIEMClientFactory.list_supported()
        assert "broken" not in factory.SIEM_REGISTRY
    finally:
        factory.SIEM_REGISTRY.pop("graylog", None)
