# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
import os

from siem_pulse import __version__
from siem_pulse.cli import load_env_file
from siem_pulse.siem_clients.qradar_client import QRadarClient


def test_mock_seed_gives_repeatable_results():
    config = {"siem": {"mock_mode": True, "mock_seed": 7}}
    device = {"device_name": "fw", "ip_address": "10.0.0.1"}
    first = QRadarClient(config).get_last_log_time(device)
    second = QRadarClient(config).get_last_log_time(device)
    # Same simulated age (to the second) on every run
    assert abs((first - second).total_seconds()) < 1


def test_env_file_is_loaded_without_overriding(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("SIEM_PULSE_TEST_A=from-file\nSIEM_PULSE_TEST_B=from-file\n")
    monkeypatch.setenv("SIEM_PULSE_TEST_B", "already-set")
    monkeypatch.delenv("SIEM_PULSE_TEST_A", raising=False)
    assert load_env_file(str(env))
    assert os.environ["SIEM_PULSE_TEST_A"] == "from-file"
    assert os.environ["SIEM_PULSE_TEST_B"] == "already-set"
    monkeypatch.delenv("SIEM_PULSE_TEST_A")


def test_missing_env_file_is_fine(tmp_path):
    assert load_env_file(str(tmp_path / "nope.env")) is False


def test_version_is_set():
    assert __version__.count(".") == 2


def test_packaged_templates_match_repo_files():
    """siem-pulse --init copies these; keep them identical to the repo versions."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    templates = root / "siem_pulse" / "templates"
    assert (templates / "config.yaml").read_text() == (root / "config.yaml").read_text()
    assert (templates / "env.example").read_text() == (root / ".env.example").read_text()
    assert (templates / "sample_devices.xlsx").read_bytes() == (root / "sample_devices.xlsx").read_bytes()


def test_init_creates_starter_files(tmp_path, capsys):
    from siem_pulse.cli import init_project
    assert init_project(tmp_path) == 0
    assert {p.name for p in tmp_path.iterdir()} == {"config.yaml", ".env.example", "sample_devices.xlsx"}
    init_project(tmp_path)
    assert "skip" in capsys.readouterr().out
