"""
base_client.py
==============
Abstract base class for all SIEM API clients.
Each SIEM implementation must inherit this and implement `get_last_log_time`.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional


class BaseSIEMClient(ABC):
    """
    Base class for SIEM clients.
    All SIEM implementations must provide get_last_log_time().
    """

    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.timeout = config.get("siem", {}).get("timeout_seconds", 30)
        self.mock_mode = config.get("siem", {}).get("mock_mode", True)

    @abstractmethod
    def get_last_log_time(self, device: Dict[str, Any]) -> Optional[datetime]:
        """
        Fetch the last log received timestamp for a given device.

        Args:
            device: Dict containing at minimum:
                    - device_name (str)
                    - ip_address  (str)

        Returns:
            datetime object of the last log event, or None if unavailable.
        """
        pass

    def _build_headers(self, extra: dict = None) -> dict:
        """Build common HTTP headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers
