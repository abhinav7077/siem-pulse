# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
detection.py
============
Catches log sources that are "alive but broken": they still send *something*,
so the last-seen check passes, but the data is not what the SOC relies on.

config.yaml:

    detection:
      enabled: true
      window_hours: 1              # activity window measured each run
      baseline_days: 7             # history used for the baseline
      min_samples: 12              # samples needed before volume drops are judged
      drop_ratio: 0.2              # alert below 20% of the median events/hour
      unparsed_ratio: 0.2          # alert when over 20% of events are unparsed
      max_clock_skew_minutes: 15   # alert when device time and SIEM time differ more
      findings_status: degraded    # degraded (alert) | healthy (report only)

Checks, for devices whose last-seen check is healthy:
    volume drop       events/hour vs the median of the last `baseline_days`
    volume floor      `min_events_per_hour` inventory column
    missing log types `expected_log_types` column vs types seen in the window
    unparsed events   share of events the SIEM could not parse
    clock skew        largest gap between event time and receive time

Needs a connector that reports metrics: QRadar, Splunk, Elastic, Sentinel,
FortiSIEM (lookup: grouped). Others are skipped. Each check costs one query
per SIEM tenant per run.
"""

import logging
import statistics
from typing import Any, Dict, List, Optional

from .siem_clients.base_client import SIEMError
from .siem_clients.factory import SIEMClientFactory

logger = logging.getLogger(__name__)

DEFAULTS = {
    "enabled": False,
    "window_hours": 1,
    "baseline_days": 7,
    "min_samples": 12,
    "drop_ratio": 0.2,
    "unparsed_ratio": 0.2,
    "max_clock_skew_minutes": 15,
    "findings_status": "degraded",
}


def settings(config: dict) -> Dict[str, Any]:
    return {**DEFAULTS, **(config.get("detection") or {})}


def evaluate(
    device: Dict[str, Any],
    metrics: Dict[str, Any],
    history: List[Dict[str, Any]],
    cfg: Dict[str, Any],
) -> List[str]:
    """Return human-readable findings for one device (empty list = all good)."""
    findings = []
    window = float(metrics.get("window_hours") or cfg["window_hours"]) or 1.0
    events = int(metrics.get("events") or 0)
    per_hour = events / window

    past = [h["events_per_hour"] for h in history if h.get("events_per_hour") is not None]
    if past and len(past) >= int(cfg["min_samples"]):
        median = statistics.median(past)
        if median > 0 and per_hour < median * float(cfg["drop_ratio"]):
            findings.append(
                f"event volume {per_hour:,.0f}/h is below {float(cfg['drop_ratio']):.0%} of the "
                f"{cfg['baseline_days']}-day median ({median:,.0f}/h)"
            )

    floor = device.get("min_events_per_hour")
    if floor is not None and per_hour < float(floor):
        findings.append(f"event volume {per_hour:,.0f}/h is below the minimum of {float(floor):,.0f}/h")

    expected = [t.lower() for t in device.get("expected_log_types") or []]
    observed = [str(t).lower() for t in metrics.get("log_types") or []]
    missing = [t for t in expected if not any(t in o for o in observed)]
    if missing:
        findings.append(f"missing log types: {', '.join(missing)}")

    unparsed = int(metrics.get("unparsed") or 0)
    if events and unparsed / events > float(cfg["unparsed_ratio"]):
        findings.append(f"{unparsed / events:.0%} of events are unparsed")

    skew = metrics.get("max_skew_seconds")
    if skew is not None and float(skew) > float(cfg["max_clock_skew_minutes"]) * 60:
        findings.append(f"clock skew up to {float(skew) / 60:,.0f} min between device and SIEM")
    return findings


def run_detection(results: List[Dict[str, Any]], config: dict, store, now=None) -> int:
    """Add `metrics` / `findings` to healthy results; returns how many devices have findings."""
    cfg = settings(config)
    if not cfg["enabled"]:
        return 0
    window = float(cfg["window_hours"])
    failed_tenants: Dict[tuple, str] = {}
    samples, flagged = [], 0

    for r in results:
        if r["status"] != "healthy":
            continue
        tenant = SIEMClientFactory.tenant_key(r)
        if tenant in failed_tenants:
            continue
        client = SIEMClientFactory.get_client_for_device(r, config)
        try:
            metrics: Optional[Dict[str, Any]] = client.metrics_for_device(r, window)
        except (SIEMError, NotImplementedError) as e:
            failed_tenants[tenant] = str(e)
            logger.warning(f"Detection skipped for {client.tenant_label}: {e}")
            continue
        if metrics is None:
            continue

        history = store.metric_history(r["device_key"], int(cfg["baseline_days"])) if store else []
        findings = evaluate(r, metrics, history, cfg)
        events = int(metrics.get("events") or 0)
        r["metrics"] = {
            "events_per_hour": round(events / window, 2),
            "log_types": metrics.get("log_types") or [],
            "unparsed_ratio": round((metrics.get("unparsed") or 0) / events, 4) if events else None,
            "max_skew_seconds": metrics.get("max_skew_seconds"),
        }
        samples.append({"device_key": r["device_key"], **r["metrics"]})
        if findings:
            flagged += 1
            r["findings"] = findings
            if str(cfg["findings_status"]).lower() == "degraded":
                r["status"] = "degraded"

    if store and samples:
        store.add_metrics(samples)
    if flagged:
        logger.info(f"Detection: {flagged} device(s) with log quality findings")
    return flagged
