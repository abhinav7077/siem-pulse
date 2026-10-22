# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
excel_reader.py
===============
Reads the device inventory from an Excel (.xlsx/.xls), CSV or YAML file.
The format is picked from the file extension.

YAML files hold a list of devices, or a mapping with a `devices:` list:

    devices:
      - device_name: fw-01
        ip_address: 10.0.0.1
        siem_platform: qradar
        client_name: Acme Corp
        auth_ref: acme

Expected columns:
    device_name     - Hostname or label for the device
    ip_address      - IP address of the device
    siem_platform   - A platform registered in siem_clients/factory.py
                      (seceon | qradar | fortisiem)
    client_name     - (Optional) Name of the client/tenant
    api_endpoint    - (Optional) Override API endpoint for this device
    auth_ref        - (Optional) Reference key to a specific credential set
    notes           - (Optional) Free-text notes
"""

import logging
from pathlib import Path
from typing import List, Dict, Any

import pandas as pd
import yaml

from .siem_clients.factory import SIEMClientFactory

logger = logging.getLogger(__name__)

REQUIRED_COLUMNS = {"device_name", "ip_address", "siem_platform"}
OPTIONAL_COLUMNS = {"client_name", "api_endpoint", "auth_ref", "notes"}

SUPPORTED_SIEMS = set(SIEMClientFactory.list_supported())


class ExcelReader:
    """Reads and validates device inventory from Excel."""

    def __init__(self, file_path: str, sheet_name: str = "Devices"):
        self.file_path = Path(file_path)
        self.sheet_name = sheet_name

    def load_devices(self) -> List[Dict[str, Any]]:
        """
        Load and validate device list from Excel.
        Returns a list of device dicts with normalized fields.
        """
        if not self.file_path.exists():
            raise FileNotFoundError(f"Device inventory file not found: {self.file_path}")

        logger.info(f"Reading device inventory from: {self.file_path}")

        try:
            df = self._read_frame()
        except Exception as e:
            raise ValueError(f"Failed to read inventory file '{self.file_path}': {e}")

        # Normalize column names: strip whitespace, lowercase
        df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

        # Validate required columns exist
        missing = REQUIRED_COLUMNS - set(df.columns)
        if missing:
            raise ValueError(
                f"Excel file is missing required columns: {missing}. "
                f"Found columns: {list(df.columns)}"
            )

        # Drop completely empty rows
        df = df.dropna(subset=list(REQUIRED_COLUMNS), how="all")

        devices = []
        for idx, row in df.iterrows():
            row_num = idx + 2  # Account for header row in Excel
            device = self._parse_row(row, row_num)
            if device:
                devices.append(device)

        logger.info(f"Successfully loaded {len(devices)} valid devices.")
        return devices

    def _read_frame(self) -> pd.DataFrame:
        """Read the inventory into a DataFrame of strings (None for blanks)."""
        suffix = self.file_path.suffix.lower()
        if suffix in (".xlsx", ".xlsm", ".xls"):
            # Read all as string to avoid type coercions
            return pd.read_excel(self.file_path, sheet_name=self.sheet_name, dtype=str)
        if suffix == ".csv":
            return pd.read_csv(self.file_path, dtype=str, skipinitialspace=True)
        if suffix in (".yaml", ".yml"):
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or []
            if isinstance(data, dict):
                data = data.get("devices", [])
            if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
                raise ValueError("YAML inventory must be a list of devices or have a 'devices:' list")
            records = [
                {str(k): (None if v is None else str(v)) for k, v in d.items()} for d in data
            ]
            return pd.DataFrame(records, dtype=object)
        raise ValueError(f"Unsupported inventory format '{suffix}' (use .xlsx, .csv or .yaml)")

    def _parse_row(self, row: pd.Series, row_num: int) -> Dict[str, Any] | None:
        """Parse a single row and validate it. Returns None if invalid."""
        device_name = self._safe_get(row, "device_name") or ""
        ip_address = self._safe_get(row, "ip_address") or ""
        siem_platform = (self._safe_get(row, "siem_platform") or "").lower()

        # Skip rows with missing required fields
        if not device_name:
            logger.warning(f"Row {row_num}: Skipping — missing device_name.")
            return None
        if not ip_address:
            logger.warning(f"Row {row_num}: Skipping '{device_name}' — missing ip_address.")
            return None
        if not siem_platform:
            logger.warning(f"Row {row_num}: Skipping '{device_name}' — missing siem_platform.")
            return None

        # Validate SIEM platform
        if siem_platform not in SUPPORTED_SIEMS:
            logger.warning(
                f"Row {row_num}: Unknown SIEM platform '{siem_platform}' for device "
                f"'{device_name}'. Supported: {SUPPORTED_SIEMS}. Skipping."
            )
            return None

        device = {
            "device_name": device_name,
            "ip_address": ip_address,
            "siem_platform": siem_platform,
            "client_name": self._safe_get(row, "client_name"),
            "api_endpoint": self._safe_get(row, "api_endpoint"),
            "auth_ref": self._safe_get(row, "auth_ref"),
            "notes": self._safe_get(row, "notes"),
        }
        return device

    @staticmethod
    def _safe_get(row: pd.Series, col: str) -> str | None:
        """Return column value or None if missing/NaN."""
        val = row.get(col, None)
        if val is None or (isinstance(val, float) and pd.isna(val)):
            return None
        text = str(val).strip()
        if not text or text.lower() in ("nan", "none"):
            return None
        return text
