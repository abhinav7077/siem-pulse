# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Phase 6: dashboard, RBAC, Prometheus, heartbeat, JSON logs, metrics textfile."""

import http.client
import json
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from siem_pulse import ops
from siem_pulse.dashboard import build_server, heartbeat_status, prometheus_metrics
from siem_pulse.log_checker import device_key
from siem_pulse.ops import JsonFormatter, check_heartbeat, write_metrics_textfile
from siem_pulse.state_store import StateStore, to_iso


def row(name, client, status="healthy", hours=1.0):
    d = {"device_name": name, "ip_address": "10.0.0.1", "siem_platform": "qradar", "client_name": client}
    return {**d, "device_key": device_key(d), "status": status, "criticality": "medium",
            "hours_since_last_log": hours, "device_type": "firewall"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "state.db")
    store = StateStore(path)
    results = [row("acme-fw", "Acme Corp"), row("acme-sw", "Acme Corp", "stale", 30),
               row("globex-fw", "Globex", "stale", 50)]
    rid = store.start_run("ALL devices")
    store.update_states(results, {})
    store.finish_run(rid, results, 2.0)
    store.close()
    return path


def start(config):
    server = build_server(config, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def get(url, token=None):
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.read().decode(), dict(response.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def test_dashboard_rbac_and_pages(db, monkeypatch):
    monkeypatch.setenv("TOKEN_SOC", "soc-token")
    monkeypatch.setenv("TOKEN_ACME", "acme-token")
    config = {"state": {"path": db}, "dashboard": {"users": [
        {"name": "soc", "token_secret": "TOKEN_SOC", "clients": "*"},
        {"name": "acme", "token_secret": "TOKEN_ACME", "clients": ["Acme Corp"]},
    ]}}
    server, base = start(config)
    try:
        assert get(base + "/")[0] == 401
        assert get(base + "/", "wrong")[0] == 401
        assert get(base + "/healthz")[0] == 200            # health needs no token

        status, body, headers = get(base + "/", "soc-token")
        assert status == 200 and "Globex" in body and "Acme Corp" in body
        assert "default-src 'none'" in headers["Content-Security-Policy"]

        summary = json.loads(get(base + "/api/summary", "acme-token")[1])
        assert summary["user"] == "acme" and set(summary["coverage"]) == {"Acme Corp"}
        assert summary["totals"]["devices"] == 2

        issues = json.loads(get(base + "/api/issues", "acme-token")[1])
        assert [i["device_name"] for i in issues] == ["acme-sw"]

        assert get(base + "/client?name=Globex", "acme-token")[0] == 403
        assert "acme-fw" in get(base + "/client?name=Acme%20Corp", "acme-token")[1]

        metrics = get(base + "/metrics", "acme-token")[1]
        assert 'client="Acme Corp"' in metrics and "Globex" not in metrics

        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.request("GET", "/?token=acme-token")
        response = conn.getresponse()
        cookie = response.getheader("Set-Cookie")
        assert response.status == 303 and response.getheader("Location") == "/"
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.request("GET", "/api/summary", headers={"Cookie": cookie.split(";")[0]})
        assert json.loads(conn.getresponse().read())["user"] == "acme"
    finally:
        server.shutdown()


def test_dashboard_refuses_public_bind_without_users(db):
    with pytest.raises(SystemExit):
        build_server({"state": {"path": db}}, "0.0.0.0", 0)
    server = build_server({"state": {"path": db}, "dashboard": {"allow_anonymous": True}}, "0.0.0.0", 0)
    server.server_close()


def test_prometheus_format(db):
    store = StateStore(db)
    text = prometheus_metrics({}, store)
    assert "siem_pulse_up 1" in text
    assert 'siem_pulse_devices{client="Globex",siem="qradar",status="stale"} 1' in text
    assert 'siem_pulse_client_coverage_score{client="Acme Corp"} 50.0' in text
    assert 'siem_pulse_device_hours_since_last_log{client="Globex",device="globex-fw",siem="qradar"} 50.00' in text


def test_heartbeat_status():
    now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
    config = {"scheduler": {"interval_minutes": 30}}
    fresh = {"finished_at": to_iso(now - timedelta(minutes=40))}
    old = {"finished_at": to_iso(now - timedelta(minutes=90))}
    assert heartbeat_status(config, fresh, now)["ok"]
    assert not heartbeat_status(config, old, now)["ok"]          # limit = 2 x 30 + 5
    assert not heartbeat_status(config, None, now)["ok"]


def test_check_heartbeat_alerts_once(tmp_path):
    store = StateStore(str(tmp_path / "s.db"))
    sent = []

    class Alerter:
        def dispatch(self, batch):
            sent.append(batch)
    assert not check_heartbeat({}, store, Alerter())
    assert not check_heartbeat({}, store, Alerter())
    assert len(sent) == 1 and sent[0].new[0]["device_name"] == "SIEM Pulse monitor"
    rid = store.start_run("x")
    store.finish_run(rid, [], 1)
    assert check_heartbeat({}, store, Alerter())


def test_ping_heartbeat(monkeypatch):
    calls = []
    monkeypatch.setattr(ops.requests, "get", lambda url, timeout: calls.append(url))
    assert not ops.ping_heartbeat({})
    assert ops.ping_heartbeat({"heartbeat": {"ping_url": "https://hc.test/abc"}})
    assert ops.ping_heartbeat({"heartbeat": {"ping_url": "https://hc.test/abc"}}, failed=True)
    assert calls == ["https://hc.test/abc", "https://hc.test/abc/fail"]


def test_metrics_textfile(db, tmp_path):
    target = tmp_path / "collector" / "siem_pulse.prom"
    path = write_metrics_textfile({"metrics": {"textfile": str(target)}}, StateStore(db))
    assert path and "siem_pulse_devices" in target.read_text()


def test_json_log_format():
    record = logging.LogRecord("siem_pulse.test", logging.WARNING, __file__, 1, "hello %s", ("world",), None)
    entry = json.loads(JsonFormatter().format(record))
    assert entry["level"] == "WARNING" and entry["message"] == "hello world" and entry["logger"] == "siem_pulse.test"
