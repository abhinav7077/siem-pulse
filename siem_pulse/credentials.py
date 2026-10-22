# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
credentials.py
==============
Where SIEM Pulse reads credentials from.

config.yaml:

    secrets:
      provider: env            # env (default) | vault | aws | azure
      fallback_to_env: true    # also try environment variables if the provider has no value

Every secret has a NAME (e.g. QRADAR_SEC_TOKEN) and an optional TENANT
(the device's auth_ref). Each provider maps that pair to its own storage:

  env    environment variable  <TENANT>_<NAME>, or <NAME> without a tenant
         (auth_ref "acme" -> ACME_QRADAR_SEC_TOKEN)

  vault  HashiCorp Vault KV v2. Secret path from `path_template`
         (default "siem-pulse/{tenant}", tenant "default" when none),
         key = NAME.
             vault:
               addr: "https://vault.example:8200"   # or env VAULT_ADDR
               mount: "secret"
               path_template: "siem-pulse/{tenant}"
               namespace: ""                         # Vault Enterprise, optional
               verify_ssl: true
         Token from env VAULT_TOKEN.

  aws    AWS Secrets Manager (needs `pip install boto3`). One JSON secret
         per tenant, id from `secret_id_template` (default
         "siem-pulse/{tenant}"), key = NAME. Uses the normal AWS credential
         chain (env vars, profile, instance role).
             aws:
               region: "us-east-1"
               secret_id_template: "siem-pulse/{tenant}"

  azure  Azure Key Vault (needs `pip install azure-identity azure-keyvault-secrets`).
         Secret name = <TENANT>-<NAME> with "_" replaced by "-"
         (ACME-QRADAR-SEC-TOKEN). Uses DefaultAzureCredential.
             azure:
               vault_url: "https://my-vault.vault.azure.net"

A tenant's lookup never falls back to the default (tenant-less) secret, so
one client's credentials are never used for another client.
"""

import json
import logging
import os
import re
import threading
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)


def env_prefix(tenant: Optional[str]) -> str:
    """'Acme Corp-1' -> 'ACME_CORP_1_' (empty string when no tenant)."""
    if not tenant:
        return ""
    return re.sub(r"[^A-Z0-9]+", "_", str(tenant).upper()).strip("_") + "_"


class SecretError(Exception):
    """The secret store could not be read (as opposed to: the secret is not set)."""


class EnvProvider:
    name = "env"

    def get(self, name: str, tenant: Optional[str] = None) -> Optional[str]:
        return os.environ.get(env_prefix(tenant) + name) or None

    def describe(self, name: str, tenant: Optional[str] = None) -> str:
        return env_prefix(tenant) + name


class _TenantDocumentProvider:
    """Base for stores that keep one key/value document per tenant."""

    name = "store"

    def __init__(self):
        self._cache: Dict[str, Dict[str, str]] = {}
        self._lock = threading.Lock()

    def _document(self, tenant: Optional[str]) -> Dict[str, str]:
        key = tenant or "default"
        with self._lock:
            if key not in self._cache:
                self._cache[key] = self._load(key)
            return self._cache[key]

    def _load(self, tenant: str) -> Dict[str, str]:
        raise NotImplementedError

    def get(self, name: str, tenant: Optional[str] = None) -> Optional[str]:
        value = self._document(tenant).get(name)
        return str(value) if value not in (None, "") else None


class VaultProvider(_TenantDocumentProvider):
    name = "vault"

    def __init__(self, cfg: dict):
        super().__init__()
        self.addr = (cfg.get("addr") or os.environ.get("VAULT_ADDR", "")).rstrip("/")
        self.mount = cfg.get("mount", "secret").strip("/")
        self.path_template = cfg.get("path_template", "siem-pulse/{tenant}")
        self.namespace = cfg.get("namespace") or os.environ.get("VAULT_NAMESPACE", "")
        self.verify = cfg.get("verify_ssl", True)
        self.timeout = cfg.get("timeout_seconds", 10)
        if not self.addr:
            raise SecretError("Vault provider needs secrets.vault.addr or VAULT_ADDR")

    def _path(self, tenant: str) -> str:
        return self.path_template.format(tenant=tenant).strip("/")

    def describe(self, name: str, tenant: Optional[str] = None) -> str:
        return f"vault:{self.mount}/{self._path(tenant or 'default')}#{name}"

    def _load(self, tenant: str) -> Dict[str, str]:
        token = os.environ.get("VAULT_TOKEN", "")
        if not token:
            raise SecretError("VAULT_TOKEN is not set")
        headers = {"X-Vault-Token": token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        url = f"{self.addr}/v1/{self.mount}/data/{self._path(tenant)}"
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=self.verify)
        except requests.exceptions.RequestException as e:
            raise SecretError(f"Cannot reach Vault at {self.addr}: {e}") from e
        if response.status_code == 404:
            return {}
        if response.status_code != 200:
            raise SecretError(f"Vault returned HTTP {response.status_code} for {url}")
        try:
            return response.json().get("data", {}).get("data", {}) or {}
        except ValueError as e:
            raise SecretError("Vault returned a non-JSON response") from e


class AwsSecretsManagerProvider(_TenantDocumentProvider):
    name = "aws"

    def __init__(self, cfg: dict):
        super().__init__()
        try:
            import boto3
        except ImportError as e:
            raise SecretError("AWS provider needs boto3: pip install boto3") from e
        self.client = boto3.client("secretsmanager", region_name=cfg.get("region"))
        self.template = cfg.get("secret_id_template", "siem-pulse/{tenant}")

    def describe(self, name: str, tenant: Optional[str] = None) -> str:
        return f"aws:{self.template.format(tenant=tenant or 'default')}#{name}"

    def _load(self, tenant: str) -> Dict[str, str]:
        secret_id = self.template.format(tenant=tenant)
        try:
            response = self.client.get_secret_value(SecretId=secret_id)
        except Exception as e:
            if type(e).__name__ == "ResourceNotFoundException" or "ResourceNotFound" in str(e):
                return {}
            raise SecretError(f"AWS Secrets Manager error for {secret_id}: {e}") from e
        try:
            data = json.loads(response.get("SecretString") or "{}")
        except ValueError as e:
            raise SecretError(f"AWS secret {secret_id} is not a JSON object") from e
        if not isinstance(data, dict):
            raise SecretError(f"AWS secret {secret_id} is not a JSON object")
        return data


class AzureKeyVaultProvider:
    name = "azure"

    def __init__(self, cfg: dict):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as e:
            raise SecretError(
                "Azure provider needs: pip install azure-identity azure-keyvault-secrets"
            ) from e
        vault_url = cfg.get("vault_url")
        if not vault_url:
            raise SecretError("Azure provider needs secrets.azure.vault_url")
        self.client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
        self._cache: Dict[str, Optional[str]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def secret_name(name: str, tenant: Optional[str] = None) -> str:
        return (env_prefix(tenant) + name).replace("_", "-")

    def describe(self, name: str, tenant: Optional[str] = None) -> str:
        return f"azure:{self.secret_name(name, tenant)}"

    def get(self, name: str, tenant: Optional[str] = None) -> Optional[str]:
        key = self.secret_name(name, tenant)
        with self._lock:
            if key not in self._cache:
                try:
                    self._cache[key] = self.client.get_secret(key).value
                except Exception as e:
                    if type(e).__name__ == "ResourceNotFoundError":
                        self._cache[key] = None
                    else:
                        raise SecretError(f"Azure Key Vault error for {key}: {e}") from e
            return self._cache[key]


class SecretResolver:
    """Reads secrets from the configured provider, optionally falling back to env."""

    def __init__(self, provider, fallback_to_env: bool = True):
        self.provider = provider
        self.env = EnvProvider()
        self.fallback_to_env = fallback_to_env and provider.name != "env"

    def get(self, name: str, tenant: Optional[str] = None) -> Optional[str]:
        value = self.provider.get(name, tenant)
        if value is None and self.fallback_to_env:
            value = self.env.get(name, tenant)
        return value

    def describe(self, name: str, tenant: Optional[str] = None) -> str:
        where = self.provider.describe(name, tenant)
        if self.fallback_to_env:
            where += f" or env {self.env.describe(name, tenant)}"
        return where


_PROVIDERS = {
    "env": lambda cfg: EnvProvider(),
    "vault": VaultProvider,
    "aws": AwsSecretsManagerProvider,
    "azure": AzureKeyVaultProvider,
}
_resolvers: Dict[int, tuple] = {}
_resolver_lock = threading.Lock()


def get_resolver(config: dict) -> SecretResolver:
    """One resolver per config object (providers cache what they read)."""
    with _resolver_lock:
        key = id(config)
        entry = _resolvers.get(key)
        if entry is None or entry[0] is not config:
            cfg = config.get("secrets", {}) or {}
            provider_name = str(cfg.get("provider", "env")).lower()
            if provider_name not in _PROVIDERS:
                raise SecretError(
                    f"Unknown secrets.provider '{provider_name}' (use {', '.join(_PROVIDERS)})"
                )
            provider = _PROVIDERS[provider_name](cfg.get(provider_name, {}) or {})
            _resolvers[key] = (config, SecretResolver(provider, cfg.get("fallback_to_env", True)))
            logger.debug(f"Secrets provider: {provider_name}")
        return _resolvers[key][1]


def get_secret(config: dict, name: str, tenant: Optional[str] = None) -> Optional[str]:
    """Convenience: read one secret using the configured provider."""
    return get_resolver(config).get(name, tenant)


def clear_cache():
    with _resolver_lock:
        _resolvers.clear()
