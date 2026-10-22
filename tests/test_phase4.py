# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Phase 4: volume baselines, log types, parsing, clock skew, coverage, ATT&CK."""

import json
import sqlite3

import pytest

from siem_pulse.alert_policy import classify
from siem_pulse.coverage import blind_spots, coverage_by_client
from siem_pulse.detection import DEFAULTS, evaluate, run_detection
from siem_pulse.log_checker import device_key
from siem_pulse.siem_clients.elastic_client import ElasticClient
from siem_pulse.siem_clients.factory import SIEMClientFactory
from siem_pulse.siem_clients.fortisiem_client import FortiSIEMClient
from siem_pulse.siem_clients.qradar_client import QRadarClient
from siem_pulse.siem_clients.sentinel_client import SentinelClient
from siem_pulse.siem_clients.splunk_client import SplunkClient
from siem_pulse.state_store import StateStore
from tests.conftest import FakeResponse

CFG = {**DEFAULTS, "enabled": True}


def device(name="fw", status="healthy", **extra):
    d = {"device_name": name, "ip_address": "10.0.0.1", "siem_platform": "qradar", "client_name": "Acme", **extra}
    return {**d, "device_key": device_key(d), "status": status}


def history(per_hour, n=24):
    return [{"events_per_hour": per_hour} for _ in range(n)]


# ─── Rules ────────────────────────────────────────────────────────────────────

def test_volume_drop_against_baseline():
    m = {"events": 50, "window_hours": 1, "log_types": [], "unparsed": 0}
    assert any("below 20%" in f for f in evaluate(device(), m, history(1000), CFG))
    assert evaluate(device(), {**m, "events": 400}, history(1000), CFG) == []
    assert evaluate(device(), m, history(1000, n=3), CFG) == []       # not enough history yet
    assert evaluate(device(), m, [], {**CFG, "min_samples": 0}) == []  # no history at all


def test_volume_floor_missing_types_unparsed_and_skew():
    d = device(min_events_per_hour=100, expected_log_types=["traffic", "system"])
    m = {"events": 60, "window_hours": 1, "log_types": ["System Notification"], "unparsed": 30,
         "max_skew_seconds": 3600}
    findings = evaluate(d, m, [], CFG)
    assert any("minimum of 100/h" in f for f in findings)
    assert "missing log types: traffic" in findings
    assert any("50% of events are unparsed" in f for f in findings)
    assert any("clock skew up to 60 min" in f for f in findings)


# ─── Run detection end to end (fake metrics) ──────────────────────────────────

class MetricsClient:
    supports_metrics = True
    tenant_label = "fake"

    def __init__(self, metrics):
        self.metrics = metrics

    def metrics_for_device(self, d, window):
        return self.metrics.get(d["device_name"])


def test_run_detection_marks_degraded_and_records_history(monkeypatch):
    store = StateStore(":memory:")
    good, bad = device("good"), device("bad", expected_log_types=["traffic"])
    stale = device("stale", status="stale")
    client = MetricsClient({"good": {"events": 900, "log_types": ["traffic"]},
                            "bad": {"events": 900, "log_types": ["system"]}})
    monkeypatch.setattr(SIEMClientFactory, "get_client_for_device", classmethod(lambda cls, d, c: client))

    flagged = run_detection([good, bad, stale], {"detection": {"enabled": True}}, store)
    assert flagged == 1
    assert good["status"] == "healthy" and bad["status"] == "degraded"
    assert bad["findings"] == ["missing log types: traffic"]
    assert "metrics" not in stale
    assert len(store.metric_history(good["device_key"])) == 1

    # degraded is an issue: it alerts like stale
    batch = classify([bad], {}, {})
    assert [i["device_name"] for i in batch.new] == ["bad"]


def test_report_only_mode(monkeypatch):
    d = device("bad", expected_log_types=["traffic"])
    client = MetricsClient({"bad": {"events": 10, "log_types": []}})
    monkeypatch.setattr(SIEMClientFactory, "get_client_for_device", classmethod(lambda cls, x, c: client))
    run_detection([d], {"detection": {"enabled": True, "findings_status": "healthy"}}, None)
    assert d["status"] == "healthy" and d["findings"]


def test_detection_disabled_by_default():
    d = device()
    assert run_detection([d], {}, None) == 0 and "metrics" not in d


# ─── Connector metrics ────────────────────────────────────────────────────────

def test_qradar_metrics_aql(http, config):
    http.add("GET", "/log_source_management/log_sources", FakeResponse(200, [
        {"id": 7, "name": "FW @ 10.0.0.1", "identifier": "10.0.0.1", "last_event_time": 1}]))
    http.add("POST", "/ariel/searches", FakeResponse(201, {"search_id": "m1"}))
    http.add("GET", "/ariel/searches/m1/results", FakeResponse(200, {"events": [
        {"logsourceid": 7, "log_type": "Access", "isunparsed": False, "events": 900, "max_lag": 2000, "min_lag": -500},
        {"logsourceid": 7, "log_type": "Unknown", "isunparsed": True, "events": 100, "max_lag": 0, "min_lag": 0},
    ]}))
    http.add("GET", "/ariel/searches/m1", FakeResponse(200, {"status": "COMPLETED"}))
    http.add("DELETE", "/ariel/searches/m1", FakeResponse(202, {}))
    m = QRadarClient(config).metrics_for_device({"device_name": "fw", "ip_address": "10.0.0.1"}, 1)
    assert m["events"] == 1000 and m["unparsed"] == 100
    assert m["log_types"] == ["Access", "Unknown"] and m["max_skew_seconds"] == 2.0
    aql = [c for c in http.calls if c["method"] == "POST"][0]["params"]["query_expression"]
    assert "GROUP BY logsourceid" in aql and "LAST 60 MINUTES" in aql


def test_splunk_metrics(http, monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "t")
    rows = [{"result": {"host": "10.0.0.1", "sourcetype": "pan:traffic", "count": "800",
                        "indexed": "1000", "latest": "940"}},
            {"result": {"host": "10.0.0.1", "sourcetype": "pan:system", "count": "200",
                        "indexed": "1000", "latest": "995"}}]
    http.add("POST", "/export", FakeResponse(200, text="\n".join(json.dumps(r) for r in rows)))
    client = SplunkClient({"siem": {"mock_mode": False, "splunk": {"base_url": "https://s.test:8089"}}})
    m = client.metrics_for_device({"device_name": "x", "ip_address": "10.0.0.1"}, 1)
    assert m["events"] == 1000 and m["log_types"] == ["pan:system", "pan:traffic"] and m["max_skew_seconds"] == 60


def test_elastic_metrics(http, monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "k")
    http.add("POST", "/_search", FakeResponse(200, {"aggregations": {"hosts": {"buckets": [
        {"key": {"name": "fw", "ip": "10.0.0.1"}, "doc_count": 500,
         "latest": {"value": 1_000_000}, "ingested": {"value": 1_120_000},
         "types": {"buckets": [{"key": "panw.traffic"}]}}]}}}))
    client = ElasticClient({"siem": {"mock_mode": False, "elastic": {"base_url": "https://es.test"}}})
    m = client.metrics_for_device({"device_name": "fw", "ip_address": "10.0.0.1"}, 2)
    assert m == {"events": 500, "log_types": ["panw.traffic"], "unparsed": 0, "max_skew_seconds": 120.0,
                 "window_hours": 2}


def test_sentinel_metrics(http, monkeypatch):
    http.add("POST", "/token", FakeResponse(200, {"access_token": "jwt"}))
    http.add("POST", "/query", FakeResponse(200, {"tables": [{
        "columns": [{"name": "Name"}, {"name": "Ip"}, {"name": "Events"}, {"name": "LogTypes"},
                    {"name": "MaxLagSeconds"}],
        "rows": [["fw", "10.0.0.1", 42, '["CommonSecurityLog"]', 30]]}]}))
    client = SentinelClient({"siem": {"mock_mode": False, "sentinel": {"workspace_id": "w", "tenant_id": "t"}}})
    m = client.metrics_for_device({"device_name": "fw", "ip_address": "10.0.0.1"}, 1)
    assert m["events"] == 42 and m["log_types"] == ["CommonSecurityLog"] and m["max_skew_seconds"] == 30


def test_fortisiem_metrics_grouped(http, config):
    config["siem"]["fortisiem"]["lookup"] = "grouped"
    http.add("POST", "/query/eventQuery", FakeResponse(200, text="q9"))
    http.add("GET", "/query/progress/q9", FakeResponse(200, text="100"))
    row = ('<event><attributes><attribute name="reptDevIpAddr">10.0.0.1</attribute>'
           '<attribute name="reptDevName">fw</attribute><attribute name="eventType">{t}</attribute>'
           '<attribute name="COUNT(*)">{n}</attribute></attributes></event>')
    http.add("GET", "/query/events/q9/", FakeResponse(200, text=(
        "<queryResult><events>" + row.format(t="FortiGate-traffic", n=90)
        + row.format(t="Unknown_FortiGate_Event", n=10) + "</events></queryResult>")))
    client = FortiSIEMClient(config)
    assert client.supports_metrics
    m = client.metrics_for_device({"device_name": "x", "ip_address": "10.0.0.1"}, 1)
    assert m["events"] == 100 and m["unparsed"] == 10
    assert "eventType,COUNT(*)" in http.calls[0]["data"].decode()


def test_unmatched_device_has_zero_volume(http, config):
    http.add("POST", "/export", FakeResponse(200, text=""))
    client = SplunkClient({"siem": {"mock_mode": False, "splunk": {"base_url": "https://s.test"}}})
    assert client.metrics_for_device({"device_name": "ghost", "ip_address": "10.9.9.9"}, 1)["events"] == 0


# ─── Coverage and ATT&CK ──────────────────────────────────────────────────────

def test_coverage_score_is_criticality_weighted():
    results = [
        device("dc", criticality="critical"),                         # weight 4, healthy
        device("fw", status="stale", criticality="critical"),         # weight 4, down
        device("web", status="degraded", criticality="medium"),       # weight 2, half
        device("old", status="stale", suppressed="snoozed"),          # excluded
    ]
    c = coverage_by_client(results)["Acme"]
    assert c["score"] == pytest.approx(100 * (4 + 1) / 10)
    assert (c["healthy"], c["down"], c["degraded"], c["suppressed"]) == (1, 1, 1, 1)


def test_attack_blind_spots():
    results = [
        device("fw-1", status="stale", device_type="firewall"),
        device("fw-2", status="error", device_type="firewall"),
        device("dc-1", status="healthy", device_type="domain_controller"),
        device("dns-1", status="healthy", device_type="dns"),
        device("nac-1", status="stale", device_type="nac"),
    ]
    spots = blind_spots(results, {"attack": {"device_types": {"nac": ["Logon Session"]}}})
    names = {s["data_source"]: s for s in spots["Acme"]}
    assert set(names) == {"Network Traffic", "Firewall"}   # Logon Session still has dc-1
    assert names["Network Traffic"]["id"] == "DS0029"
    assert names["Network Traffic"]["down"] == ["fw-1", "fw-2"]


# ─── Store migration ──────────────────────────────────────────────────────────

def test_old_database_is_migrated(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT,"
                " scope TEXT, total INTEGER, healthy INTEGER, stale INTEGER, error INTEGER, suppressed INTEGER,"
                " duration_seconds REAL)")
    con.commit()
    con.close()
    store = StateStore(str(path))
    rid = store.start_run("x")
    store.finish_run(rid, [device("fw", status="degraded", findings=["missing log types: traffic"])], 1)
    assert store.last_run()["degraded"] == 1
    assert store.run_results(rid)[0]["findings"] == "missing log types: traffic"
