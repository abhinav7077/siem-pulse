# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Phase 2: tenants, credentials, bulk lookups, reconciliation, rate limits, inventory formats."""

import threading
import time
from datetime import datetime, timezone

import pytest

from modules.excel_reader import ExcelReader
from modules.log_checker import LogChecker
from modules.reconciler import reconcile
from modules.siem_clients import base_client
from modules.siem_clients.base_client import NonRetryableError, RateLimiter, env_prefix
from modules.siem_clients.factory import SIEMClientFactory
from modules.siem_clients.fortisiem_client import FortiSIEMClient
from modules.siem_clients.qradar_client import QRadarClient
from modules.siem_clients.seceon_client import SeceonClient
from tests.conftest import FakeResponse

MS = 1_760_000_000_000
LOG_SOURCES = "/log_source_management/log_sources"


@pytest.fixture(autouse=True)
def fresh_factory():
    SIEMClientFactory.clear_cache()
    yield
    SIEMClientFactory.clear_cache()


def qradar_device(name, ip, endpoint=None, auth_ref=None, client="Acme"):
    return {"device_name": name, "ip_address": ip, "siem_platform": "qradar",
            "client_name": client, "api_endpoint": endpoint, "auth_ref": auth_ref}


# ─── Tenants and credentials ──────────────────────────────────────────────────

def test_env_prefix():
    assert env_prefix("acme") == "ACME_"
    assert env_prefix("Acme Corp-1") == "ACME_CORP_1_"
    assert env_prefix(None) == ""


def test_factory_keeps_one_client_per_tenant(config):
    a1 = SIEMClientFactory.get_client_for_device(qradar_device("a", "10.0.0.1", auth_ref="acme"), config)
    a2 = SIEMClientFactory.get_client_for_device(qradar_device("b", "10.0.0.2", auth_ref="acme"), config)
    g = SIEMClientFactory.get_client_for_device(qradar_device("c", "10.0.0.3", auth_ref="globex"), config)
    e = SIEMClientFactory.get_client_for_device(
        qradar_device("d", "10.0.0.4", endpoint="https://other.test/api/"), config)
    assert a1 is a2
    assert g is not a1 and e is not a1
    assert e.base_url == "https://other.test/api"


def test_tenant_overrides_and_prefixed_credentials(config, monkeypatch):
    monkeypatch.setenv("QRADAR_SEC_TOKEN", "default-token")
    monkeypatch.setenv("ACME_QRADAR_SEC_TOKEN", "acme-token")
    config["siem"]["qradar"]["tenants"] = {
        "acme": {"base_url": "https://qradar.acme.test/api", "verify_ssl": "/acme-ca.pem"},
    }
    acme = QRadarClient(config, auth_ref="acme")
    default = QRadarClient(config)
    assert acme.sec_token == "acme-token" and acme.base_url == "https://qradar.acme.test/api"
    assert acme.verify_ssl == "/acme-ca.pem"
    assert default.sec_token == "default-token" and default.base_url == "https://qradar.test/api"


def test_tenant_never_uses_default_credentials(http, config, monkeypatch):
    monkeypatch.setenv("QRADAR_SEC_TOKEN", "default-token")
    client = QRadarClient(config, auth_ref="globex")  # GLOBEX_QRADAR_SEC_TOKEN not set
    with pytest.raises(NonRetryableError, match="GLOBEX_QRADAR_SEC_TOKEN"):
        client.get_last_log_time(qradar_device("fw", "10.0.0.1"))
    assert http.calls == []  # nothing was sent anywhere


def test_inventory_endpoint_column_is_used(http, config, monkeypatch):
    monkeypatch.setenv("ACME_QRADAR_SEC_TOKEN", "acme-token")
    http.add("GET", "https://qradar.acme.test/api/config/event_sources" + LOG_SOURCES, FakeResponse(
        200, [{"name": "fw", "identifier": "10.0.0.1", "last_event_time": MS}]))
    device = qradar_device("fw", "10.0.0.1", endpoint="https://qradar.acme.test/api", auth_ref="acme")
    client = SIEMClientFactory.get_client_for_device(device, config)
    assert client.get_last_log_time(device) is not None
    assert http.calls[0]["headers"]["SEC"] == "acme-token"


# ─── Bulk lookups ─────────────────────────────────────────────────────────────

def test_permanent_inventory_failure_is_not_repeated_per_device(http, config):
    http.add("GET", LOG_SOURCES, FakeResponse(401, {}))
    client = QRadarClient(config)
    for i in range(5):
        with pytest.raises(NonRetryableError):
            client.get_last_log_time(qradar_device(f"d{i}", f"10.0.0.{i + 1}"))
    assert http.count("GET", LOG_SOURCES) == 1


def test_2000_devices_100_clients_bulk_run_is_fast(http, config, monkeypatch):
    """Phase 2 exit check, simulated: 100 tenants x 20 devices, one bulk call per tenant."""
    config["siem"]["qradar"]["page_size"] = 500
    devices = []
    tenants = {}
    for t in range(100):
        ref = f"client{t}"
        monkeypatch.setenv(f"{env_prefix(ref)}QRADAR_SEC_TOKEN", f"token-{t}")
        sources = []
        for d in range(20):
            ip = f"10.{t}.0.{d + 1}"
            devices.append(qradar_device(f"dev-{t}-{d}", ip, auth_ref=ref, client=f"Client {t}"))
            sources.append({"name": f"dev-{t}-{d}", "identifier": ip,
                            "last_event_time": int(time.time() * 1000)})
        tenants[f"token-{t}"] = sources

    def answer(method, url, **kwargs):
        return FakeResponse(200, tenants[kwargs["headers"]["SEC"]])
    http.add("GET", LOG_SOURCES, answer)

    checker = LogChecker(max_retries=1)
    started = time.monotonic()
    results = [checker.check_device(d, SIEMClientFactory.get_client_for_device(d, config)) for d in devices]
    elapsed = time.monotonic() - started

    assert len(results) == 2000
    assert all(r["status"] == "healthy" for r in results)
    assert http.count("GET", LOG_SOURCES) == 100   # one call per tenant, not per device
    assert elapsed < 60


def test_fortisiem_grouped_lookup(http, config):
    config["siem"]["fortisiem"].update({"lookup": "grouped", "page_size": 2})
    http.add("POST", "/query/eventQuery", FakeResponse(200, text="q1"))
    http.add("GET", "/query/progress/q1", FakeResponse(200, text="100"))

    def event(ip, name, ms):
        return (f'<event><attributes><attribute name="reptDevIpAddr">{ip}</attribute>'
                f'<attribute name="reptDevName">{name}</attribute>'
                f'<attribute name="MAX(phRecvTime)">{ms}</attribute></attributes></event>')
    http.add("GET", "/query/events/q1/0/2", FakeResponse(200, text=(
        f"<queryResult><events>{event('10.0.0.1', 'fw', MS)}{event('10.0.0.2', 'sw', MS)}</events></queryResult>")))
    http.add("GET", "/query/events/q1/2/4", FakeResponse(200, text=(
        f"<queryResult><events>{event('10.0.0.3', 'srv', MS)}</events></queryResult>")))

    client = FortiSIEMClient(config)
    assert client.supports_inventory
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        assert client.get_last_log_time({"device_name": "x", "ip_address": ip}) == datetime.fromtimestamp(
            MS / 1000, tz=timezone.utc)
    assert client.get_last_log_time({"device_name": "x", "ip_address": "10.9.9.9"}) is None
    body = http.calls[0]["data"].decode()
    assert "<GroupByClause>" in body and "MAX(phRecvTime)" in body
    assert http.count("POST", "/query/eventQuery") == 1


def test_seceon_bulk_lookup(http, config):
    config["siem"]["seceon"].update({
        "lookup": "bulk", "bulk_path": "/assets", "bulk_items_field": "data.assets",
        "bulk_ip_field": "ip", "bulk_name_field": "hostname", "timestamp_fields": ["last_seen"],
    })
    http.add("GET", "/assets", FakeResponse(200, {"data": {"assets": [
        {"ip": "10.0.0.1", "hostname": "web-01", "last_seen": "2025-10-09T08:53:20Z"},
        {"ip": "10.0.0.2", "hostname": "db-01", "last_seen": None},
    ]}}))
    client = SeceonClient(config)
    assert client.get_last_log_time({"device_name": "WEB-01", "ip_address": "1.1.1.1"}) == datetime(
        2025, 10, 9, 8, 53, 20, tzinfo=timezone.utc)
    assert client.get_last_log_time({"device_name": "db", "ip_address": "10.0.0.2"}) is None
    assert http.count("GET", "/assets") == 1


def test_qradar_paging_stops_when_range_is_ignored(http, config):
    """A server that ignores Range and repeats the full list must not loop forever."""
    everything = [{"id": i, "name": f"s{i}", "identifier": f"10.0.0.{i}", "last_event_time": MS}
                  for i in range(1, 5)]
    http.add("GET", LOG_SOURCES, FakeResponse(200, everything))  # page_size is 2
    assert len(QRadarClient(config).list_known_sources()) == 4
    assert http.count("GET", LOG_SOURCES) == 1

    http.routes.clear()
    http.calls.clear()
    http.add("GET", LOG_SOURCES, FakeResponse(200, everything[:2]))  # same page every time
    client = QRadarClient(config)
    assert len(client.list_known_sources()) == 2
    assert http.count("GET", LOG_SOURCES) == 2


# ─── Reconciliation ───────────────────────────────────────────────────────────

def test_reconcile_finds_unlisted_and_missing(http, config):
    http.add("GET", LOG_SOURCES, FakeResponse(200, [
        {"name": "fw", "identifier": "10.0.0.1", "last_event_time": MS},
        {"name": "dc01", "identifier": "dc01.corp", "last_event_time": MS},
        {"name": "shadow-it-box", "identifier": "10.0.0.66", "last_event_time": MS},
    ]))
    devices = [
        qradar_device("fw", "10.0.0.1"),
        qradar_device("DC01", "10.0.0.5"),
        qradar_device("typo-srv", "10.0.0.99"),
    ]
    result = reconcile(devices, config)
    assert [r["identifier"] for r in result["unlisted"]] == ["10.0.0.66"]
    assert [r["name"] for r in result["not_found"]] == ["typo-srv"]
    assert result["unlisted"][0]["last_seen"].endswith("UTC")


def test_reconcile_skips_modes_without_inventory(config):
    devices = [{"device_name": "fw", "ip_address": "10.0.0.1", "siem_platform": "fortisiem"}]
    result = reconcile(devices, config)
    assert "lookup: grouped" in result["skipped"][0]["reason"]


# ─── Rate and concurrency limits ──────────────────────────────────────────────

def test_rate_limiter_spaces_requests(monkeypatch):
    sleeps = []
    monkeypatch.setattr(base_client.time, "sleep", sleeps.append)
    limiter = RateLimiter(rate=10)
    for _ in range(3):
        limiter.wait()
    assert len(sleeps) == 2 and all(0 < s <= 0.2 for s in sleeps)


def test_max_concurrent_requests(http, config):
    config["siem"]["qradar"]["max_concurrent_requests"] = 2
    active, peak, lock = [0], [0], threading.Lock()

    def slow(method, url, **kwargs):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return FakeResponse(200, {})
    http.add("GET", "/x", slow)

    client = QRadarClient(config)
    threads = [threading.Thread(target=client._request, args=("GET", "https://qradar.test/api/x"))
               for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak[0] == 2


# ─── Inventory formats ────────────────────────────────────────────────────────

def test_csv_and_yaml_inventories(tmp_path):
    csv_file = tmp_path / "devices.csv"
    csv_file.write_text(
        "device_name,ip_address,siem_platform,client_name,auth_ref\n"
        "fw-01,10.0.0.1,qradar,Acme,acme\n"
        ",10.0.0.2,qradar,Acme,\n"
    )
    yaml_file = tmp_path / "devices.yaml"
    yaml_file.write_text(
        "devices:\n"
        "  - {device_name: fw-01, ip_address: 10.0.0.1, siem_platform: QRadar, auth_ref: acme}\n"
        "  - {device_name: no-ip, siem_platform: qradar}\n"
    )
    for path in (csv_file, yaml_file):
        devices = ExcelReader(str(path)).load_devices()
        assert len(devices) == 1
        assert devices[0]["siem_platform"] == "qradar" and devices[0]["auth_ref"] == "acme"


def test_unsupported_inventory_format(tmp_path):
    path = tmp_path / "devices.txt"
    path.write_text("x")
    with pytest.raises(ValueError, match="Unsupported inventory format"):
        ExcelReader(str(path)).load_devices()
