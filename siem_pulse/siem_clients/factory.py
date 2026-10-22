# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
factory.py
==========
Factory for creating SIEM client instances based on platform name.
To add a new SIEM, register it in SIEM_REGISTRY below.
"""

import logging
import threading
from typing import Any, Dict, Optional, Tuple

from .base_client import BaseSIEMClient
from .seceon_client import SeceonClient
from .qradar_client import QRadarClient
from .fortisiem_client import FortiSIEMClient

logger = logging.getLogger(__name__)

# ─── Registry: map platform name → client class ────────────────────────────
# To add a new SIEM, just add an entry here and create the corresponding module.
SIEM_REGISTRY: Dict[str, type] = {
    "seceon": SeceonClient,
    "qradar": QRadarClient,
    "fortisiem": FortiSIEMClient,
}


class SIEMClientFactory:
    """
    Factory class for instantiating SIEM clients.

    One client is kept per tenant, identified by
    (platform, api_endpoint, auth_ref). Devices of the same tenant share a
    client, so they share its HTTP connections, rate limits and bulk cache,
    and never use another tenant's credentials.

    Usage:
        client = SIEMClientFactory.get_client_for_device(device, config)
        ts = client.get_last_log_time(device)
    """

    _cache: Dict[Tuple[str, str, str], BaseSIEMClient] = {}
    _lock = threading.Lock()

    @staticmethod
    def tenant_key(device: Dict[str, Any]) -> Tuple[str, str, str]:
        """(platform, api_endpoint, auth_ref) for a device; blanks mean defaults."""
        return (
            str(device.get("siem_platform") or "").lower().strip(),
            str(device.get("api_endpoint") or "").strip().rstrip("/"),
            str(device.get("auth_ref") or "").strip(),
        )

    @classmethod
    def get_client_for_device(cls, device: Dict[str, Any], config: dict) -> BaseSIEMClient:
        """Return the (cached) client for the tenant this device belongs to."""
        platform, endpoint, auth_ref = cls.tenant_key(device)
        return cls.get_client(platform, config, base_url=endpoint or None, auth_ref=auth_ref or None)

    @classmethod
    def get_client(
        cls,
        siem_name: str,
        config: dict,
        base_url: Optional[str] = None,
        auth_ref: Optional[str] = None,
    ) -> BaseSIEMClient:
        """
        Return a (cached) SIEM client instance for the given platform and tenant.

        Raises:
            ValueError: If siem_name is not registered.
        """
        siem_name = siem_name.lower().strip()
        if siem_name not in SIEM_REGISTRY:
            raise ValueError(
                f"Unknown SIEM platform: '{siem_name}'. "
                f"Supported: {list(SIEM_REGISTRY.keys())}"
            )

        key = (siem_name, (base_url or "").rstrip("/"), auth_ref or "")
        with cls._lock:
            if key not in cls._cache:
                client_class = SIEM_REGISTRY[siem_name]
                cls._cache[key] = client_class(config, base_url=base_url, auth_ref=auth_ref)
                logger.debug(f"Created {client_class.__name__} for tenant {key}")
            return cls._cache[key]

    @classmethod
    def clear_cache(cls):
        """Forget all clients (used by tests and config reloads)."""
        with cls._lock:
            cls._cache.clear()

    @classmethod
    def list_supported(cls):
        """Return list of registered SIEM platform names."""
        return list(SIEM_REGISTRY.keys())
