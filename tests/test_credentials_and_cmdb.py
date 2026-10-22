# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Phase 2: secrets-manager providers and ServiceNow CMDB inventory."""

import json
import sys
import types

import pytest

from siem_pulse import credentials, inventory_sources
from siem_pulse.credentials import AzureKeyVaultProvider, SecretError, get_resolver, get_secret
from siem_pulse.inventory_sources import ServiceNowInventory, load_inventory
from siem_pulse.siem_clients.base_client import NonRetryableError
from siem_pulse.siem_clients.qradar_client import QRadarClient
from tests.conftest import FakeResponse


@pytest.fixture(autouse=True)
def clear():
    credentials.clear_cache()
    yield
    credentials.clear_cache()


# ─── Vault ────────────────────────────────────────────────────────────────────

def vault_config():
    return {"secrets": {"provider": "vault", "fallback_to_env": False,
                        "vault": {"addr": "https://vault.test", "mount": "kv"}},
            "siem": {"mock_mode": False, "qradar": {"base_url": "https://q.test/api"}}}


def test_vault_reads_per_tenant_documents(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "vt")
    calls = []

    def fake_get(url, headers=None, **kwargs):
        calls.append(url)
        assert headers["X-Vault-Token"] == "vt"
        docs = {
            "https://vault.test/v1/kv/data/siem-pulse/acme": {"QRADAR_SEC_TOKEN": "acme-token"},
            "https://vault.test/v1/kv/data/siem-pulse/default": {"QRADAR_SEC_TOKEN": "default-token"},
        }
        if url not in docs:
            return FakeResponse(404, {})
        return FakeResponse(200, {"data": {"data": docs[url]}})
    monkeypatch.setattr(credentials.requests, "get", fake_get)

    config = vault_config()
    assert QRadarClient(config, auth_ref="acme").sec_token == "acme-token"
    assert QRadarClient(config).sec_token == "default-token"
    assert QRadarClient(config, auth_ref="acme").sec_token == "acme-token"
    assert calls.count("https://vault.test/v1/kv/data/siem-pulse/acme") == 1  # cached

    globex = QRadarClient(config, auth_ref="globex")   # no document: missing, no fallback
    with pytest.raises(NonRetryableError, match="vault:kv/siem-pulse/globex#QRADAR_SEC_TOKEN"):
        globex._request("GET", "https://q.test/api/x")


def test_vault_without_token_reports_error(monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    client = QRadarClient(vault_config(), auth_ref="acme")
    with pytest.raises(NonRetryableError, match="VAULT_TOKEN"):
        client._request("GET", "https://q.test/api/x")


def test_fallback_to_env(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "vt")
    monkeypatch.setattr(credentials.requests, "get", lambda *a, **k: FakeResponse(404, {}))
    monkeypatch.setenv("ACME_QRADAR_SEC_TOKEN", "env-token")
    config = vault_config()
    config["secrets"]["fallback_to_env"] = True
    assert get_secret(config, "QRADAR_SEC_TOKEN", "acme") == "env-token"
    assert get_secret(config, "QRADAR_SEC_TOKEN", "globex") is None


# ─── AWS / Azure (SDKs faked) ─────────────────────────────────────────────────

def test_aws_secrets_manager(monkeypatch):
    class NotFound(Exception):
        pass
    NotFound.__name__ = "ResourceNotFoundException"

    class FakeClient:
        def get_secret_value(self, SecretId):
            if SecretId == "sp/acme":
                return {"SecretString": json.dumps({"QRADAR_SEC_TOKEN": "aws-acme"})}
            raise NotFound()
    fake_boto3 = types.SimpleNamespace(client=lambda service, region_name=None: FakeClient())
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    config = {"secrets": {"provider": "aws", "fallback_to_env": False,
                          "aws": {"region": "eu-west-1", "secret_id_template": "sp/{tenant}"}}}
    assert get_secret(config, "QRADAR_SEC_TOKEN", "acme") == "aws-acme"
    assert get_secret(config, "QRADAR_SEC_TOKEN", "globex") is None


def test_azure_key_vault(monkeypatch):
    class NotFound(Exception):
        pass
    NotFound.__name__ = "ResourceNotFoundError"
    store = {"ACME-QRADAR-SEC-TOKEN": "az-acme"}

    class FakeSecretClient:
        def __init__(self, vault_url, credential):
            assert vault_url == "https://kv.test"

        def get_secret(self, name):
            if name not in store:
                raise NotFound()
            return types.SimpleNamespace(value=store[name])

    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = lambda: object()
    secrets_mod = types.ModuleType("azure.keyvault.secrets")
    secrets_mod.SecretClient = FakeSecretClient
    monkeypatch.setitem(sys.modules, "azure", types.ModuleType("azure"))
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault", types.ModuleType("azure.keyvault"))
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", secrets_mod)

    config = {"secrets": {"provider": "azure", "fallback_to_env": False,
                          "azure": {"vault_url": "https://kv.test"}}}
    assert get_secret(config, "QRADAR_SEC_TOKEN", "acme") == "az-acme"
    assert get_secret(config, "QRADAR_SEC_TOKEN", "globex") is None
    assert AzureKeyVaultProvider.secret_name("SECEON_API_KEY", "Acme Corp") == "ACME-CORP-SECEON-API-KEY"


def test_unknown_provider():
    with pytest.raises(SecretError):
        get_resolver({"secrets": {"provider": "keepass"}})


# ─── ServiceNow CMDB ──────────────────────────────────────────────────────────

def snow_config():
    return {"devices": {"source": "servicenow", "servicenow": {
        "instance_url": "https://acme.service-now.com/", "table": "cmdb_ci_netgear",
        "query": "operational_status=1", "page_size": 2,
        "field_map": {"criticality": "u_criticality"},
        "defaults": {"siem_platform": "qradar"},
    }}}


def test_servicenow_inventory_pages_and_maps_fields(monkeypatch):
    monkeypatch.setenv("SERVICENOW_USER", "svc")
    monkeypatch.setenv("SERVICENOW_PASS", "pw")
    pages = [
        [{"name": "fw-01", "ip_address": "10.0.0.1", "u_siem_platform": "FortiSIEM",
          "company": {"display_value": "Acme Corp", "value": "abc123"}, "u_criticality": "high"},
         {"name": "sw-01", "ip_address": "10.0.0.2", "u_siem_platform": "", "company": "Acme Corp"}],
        [{"name": "", "ip_address": "10.0.0.3", "u_siem_platform": "qradar", "company": "Acme Corp"}],
    ]
    seen = []

    def fake_get(url, params=None, auth=None, **kwargs):
        seen.append(params)
        assert url == "https://acme.service-now.com/api/now/table/cmdb_ci_netgear"
        assert auth == ("svc", "pw")
        return FakeResponse(200, {"result": pages[params["sysparm_offset"] // 2]})
    monkeypatch.setattr(inventory_sources.requests, "get", fake_get)

    devices = load_inventory(snow_config(), device_file="ignored.xlsx")
    assert [d["device_name"] for d in devices] == ["fw-01", "sw-01"]   # row without a name is skipped
    assert devices[0]["siem_platform"] == "fortisiem"
    assert devices[0]["client_name"] == "Acme Corp"
    assert devices[1]["siem_platform"] == "qradar"                     # from defaults
    assert seen[0]["sysparm_query"] == "operational_status=1"
    assert [p["sysparm_offset"] for p in seen] == [0, 2]
    assert "u_criticality" in seen[0]["sysparm_fields"]


def test_servicenow_requires_credentials(monkeypatch):
    monkeypatch.delenv("SERVICENOW_USER", raising=False)
    monkeypatch.delenv("SERVICENOW_PASS", raising=False)
    with pytest.raises(ValueError, match="SERVICENOW_USER"):
        ServiceNowInventory(snow_config()).load_devices()
