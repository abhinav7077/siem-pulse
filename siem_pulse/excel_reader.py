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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd
import yaml

from .siem_clients.factory import SIEMClientFactory

logger = logging.getLogger(__name__)


def parse_datetime(value: str) -> Optional[datetime]:
    """Parse '2026-10-25', '2026-10-25 08:00' or ISO 8601 into an aware UTC datetime."""
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = pd.to_datetime(text).to_pydatetime()
        except (ValueError, TypeError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

REQUIRED_COLUMNS = {"device_name", "ip_address", "siem_platform"}
OPTIONAL_COLUMNS = {
    "client_name", "api_endpoint", "auth_ref", "notes",
    # Alerting (Phase 3)
    "threshold_hours",      # hours without logs before this device is stale
    "criticality",          # critical | high | medium | low
    "snooze_until",         # ISO date/time — no alerts until then
    # Detection (Phase 4)
    "device_type",          # e.g. firewall, domain_controller, edr — used for ATT&CK coverage
    "expected_log_types",   # e.g. "traffic;system" — log types the device should send
    "min_events_per_hour",  # optional absolute volume floor
}
CRITICALITY_LEVELS = ("critical", "high", "medium", "low")

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
            raise ValueError(f"Failed to read inventory file '{self.file_path}': {e}") from e
        return self.devices_from_frame(df, source=str(self.file_path))

    @classmethod
    def from_records(cls, records: List[Dict[str, Any]], source: str = "records") -> List[Dict[str, Any]]:
        """Validate devices that came from somewhere other than a file (e.g. a CMDB)."""
        frame = pd.DataFrame(
            [{str(k): (None if v is None else str(v)) for k, v in r.items()} for r in records],
            dtype=object,
        )
        if frame.empty:
            frame = pd.DataFrame(columns=sorted(REQUIRED_COLUMNS))
        return cls("<memory>").devices_from_frame(frame, source=source)

    def devices_from_frame(self, df: pd.DataFrame, source: str = "inventory") -> List[Dict[str, Any]]:
        """Normalise columns, validate rows and return device dicts."""
        # Normalize column names: strip whitespace, lowercase
        df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

        # Validate required columns exist
        missing = REQUIRED_COLUMNS - set(df.columns)
        if missing:
            raise ValueError(
                f"{source} is missing required columns: {missing}. "
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

        # Validate SIEM platform (read live so plugin connectors are included)
        supported = set(SIEMClientFactory.list_supported())
        if siem_platform not in supported:
            logger.warning(
                f"Row {row_num}: Unknown SIEM platform '{siem_platform}' for device "
                f"'{device_name}'. Supported: {sorted(supported)}. Skipping."
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

        # Optional columns, validated; a bad value is dropped with a warning
        threshold = self._safe_get(row, "threshold_hours")
        if threshold is not None:
            try:
                device["threshold_hours"] = float(threshold)
                if device["threshold_hours"] <= 0:
                    raise ValueError
            except ValueError:
                logger.warning(f"Row {row_num}: ignoring invalid threshold_hours '{threshold}'")
                device.pop("threshold_hours", None)

        criticality = (self._safe_get(row, "criticality") or "").lower()
        if criticality:
            if criticality in CRITICALITY_LEVELS:
                device["criticality"] = criticality
            else:
                logger.warning(
                    f"Row {row_num}: ignoring criticality '{criticality}' "
                    f"(use {', '.join(CRITICALITY_LEVELS)})"
                )

        snooze = self._safe_get(row, "snooze_until")
        if snooze:
            parsed = parse_datetime(snooze)
            if parsed:
                device["snooze_until"] = parsed
            else:
                logger.warning(f"Row {row_num}: ignoring invalid snooze_until '{snooze}'")

        min_eph = self._safe_get(row, "min_events_per_hour")
        if min_eph is not None:
            try:
                device["min_events_per_hour"] = float(min_eph)
            except ValueError:
                logger.warning(f"Row {row_num}: ignoring invalid min_events_per_hour '{min_eph}'")

        device_type = self._safe_get(row, "device_type")
        if device_type:
            device["device_type"] = device_type.lower().replace(" ", "_")

        log_types = self._safe_get(row, "expected_log_types")
        if log_types:
            device["expected_log_types"] = [
                t.strip().lower() for t in log_types.replace(",", ";").split(";") if t.strip()
            ]
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
