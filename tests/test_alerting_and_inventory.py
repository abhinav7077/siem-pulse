# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
from pathlib import Path

from siem_pulse.alert_policy import AlertBatch
from siem_pulse.alerting import AlertManager
from siem_pulse.channels.summary import EmailChannel
from siem_pulse.excel_reader import SUPPORTED_SIEMS, ExcelReader
from siem_pulse.siem_clients.factory import SIEM_REGISTRY

ROOT = Path(__file__).resolve().parent.parent


def test_email_html_is_escaped_and_footer_is_valid():
    stale = [{"device_name": "<script>x</script>", "client_name": None, "status": "stale",
              "siem_platform": "qradar", "ip_address": "10.0.0.1", "last_log_time": "a & b"}]
    batch = AlertBatch(new=stale)
    body = EmailChannel("email", {}, {}).build_html(batch)
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "a &amp; b" in body
    assert "siem-pulse --dry-run" in body
    assert '--client "ALL devices"' not in body


def test_preview_command_uses_filters():
    cmd = AlertManager._preview_command("qradar", "Acme Corp")
    assert cmd == 'siem-pulse --dry-run --siem qradar --client "Acme Corp"'


def test_supported_siems_come_from_registry():
    assert SUPPORTED_SIEMS == set(SIEM_REGISTRY)


def test_sample_inventory_loads():
    devices = ExcelReader(str(ROOT / "sample_devices.xlsx"), sheet_name="Devices").load_devices()
    assert len(devices) == 15
