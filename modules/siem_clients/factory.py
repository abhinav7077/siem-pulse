"""
factory.py
==========
Factory for creating SIEM client instances based on platform name.
To add a new SIEM, register it in SIEM_REGISTRY below.
"""

import logging
from typing import Dict

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

    Usage:
        client = SIEMClientFactory.get_client("qradar", config)
        ts = client.get_last_log_time(device)
    """

    _cache: Dict[str, BaseSIEMClient] = {}

    @classmethod
    def get_client(cls, siem_name: str, config: dict) -> BaseSIEMClient:
        """
        Return a (cached) SIEM client instance for the given platform.

        Args:
            siem_name: Lowercase SIEM platform name (e.g., 'qradar')
            config:    Full config dict

        Returns:
            An instance of the appropriate SIEM client.

        Raises:
            ValueError: If siem_name is not registered.
        """
        siem_name = siem_name.lower().strip()

        if siem_name not in SIEM_REGISTRY:
            raise ValueError(
                f"Unknown SIEM platform: '{siem_name}'. "
                f"Supported: {list(SIEM_REGISTRY.keys())}"
            )

        # Cache clients so we don't re-instantiate per device
        if siem_name not in cls._cache:
            client_class = SIEM_REGISTRY[siem_name]
            cls._cache[siem_name] = client_class(config)
            logger.debug(f"Created new {client_class.__name__} instance.")

        return cls._cache[siem_name]

    @classmethod
    def list_supported(cls):
        """Return list of registered SIEM platform names."""
        return list(SIEM_REGISTRY.keys())
