# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
ops.py
======
Running SIEM Pulse in production: structured logs, heartbeats and metrics files.

config.yaml:

    logging:
      format: text                 # text | json (one JSON object per line, for log shippers)

    heartbeat:
      ping_url: ""                 # e.g. https://hc-ping.com/<uuid> (Healthchecks.io, Cronitor,
      ping_url_secret: ""          #   Uptime Kuma push…), or a secret holding the URL
      ping_on_failure: true        # call <ping_url>/fail when a run crashes
      max_age_minutes: 125         # /healthz and --check-heartbeat (default 2 x interval + 5)

    metrics:
      textfile: ""                 # write Prometheus metrics here after each run
                                   #   (node_exporter textfile collector), e.g.
                                   #   /var/lib/node_exporter/textfile/siem_pulse.prom
      per_device: true             # include one series per device

`siem-pulse --check-heartbeat` (run it from a separate cron/timer) alerts the
default channels once when no run has finished within max_age_minutes, and
exits with code 2 so schedulers mark it failed.
"""

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Optional

import requests

from .credentials import get_secret

logger = logging.getLogger(__name__)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def heartbeat_url(config: dict) -> Optional[str]:
    cfg = config.get("heartbeat") or {}
    if cfg.get("ping_url_secret"):
        return get_secret(config, cfg["ping_url_secret"])
    return cfg.get("ping_url") or None


def ping_heartbeat(config: dict, failed: bool = False) -> bool:
    url = heartbeat_url(config)
    if not url:
        return False
    cfg = config.get("heartbeat") or {}
    if failed and not cfg.get("ping_on_failure", True):
        return False
    target = url.rstrip("/") + ("/fail" if failed else "")
    try:
        requests.get(target, timeout=10)
        return True
    except requests.exceptions.RequestException as e:
        logger.warning(f"Heartbeat ping failed: {e}")
        return False


def write_metrics_textfile(config: dict, store) -> Optional[str]:
    path = (config.get("metrics") or {}).get("textfile")
    if not path:
        return None
    from .dashboard import prometheus_metrics
    text = prometheus_metrics(config, store)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    # Write atomically so the collector never reads half a file
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".siem_pulse.", suffix=".prom")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    return path


def check_heartbeat(config: dict, store, alerter) -> bool:
    """True when healthy. Alerts once per outage of the monitor itself."""
    from .alert_policy import AlertBatch
    from .dashboard import heartbeat_status

    status = heartbeat_status(config, store.last_run())
    last_alert = store.get_meta("heartbeat_alert_for")
    if status["ok"]:
        if last_alert:
            store.set_meta("heartbeat_alert_for", "")
        return True
    marker = status["last_run_finished_at"] or "never"
    if last_alert != marker:
        age = f"{status['age_minutes']:.0f} minutes" if status["age_minutes"] is not None else "ever"
        item = {
            "device_key": "siem-pulse|monitor", "device_name": "SIEM Pulse monitor", "ip_address": "-",
            "client_name": "(monitor)", "siem_platform": "siem-pulse", "criticality": "critical",
            "status": "error", "error": f"no completed check run for {age} (limit {status['max_age_minutes']:.0f})",
        }
        alerter.dispatch(AlertBatch(scope="SIEM Pulse self-check", new=[item]))
        store.set_meta("heartbeat_alert_for", marker)
    return False
