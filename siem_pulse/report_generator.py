# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
report_generator.py
===================
Generates summary reports from device check results.

Output formats:
  - Console table (always, sorted: stale/error first, then healthy)
  - CSV file (saved to reports/ with filter context in filename)

Supports filter context (--siem / --client) in filenames and headers
so filtered runs don't overwrite full-run reports.
"""

import csv
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _slug(value: str) -> str:
    """Convert a string to a safe filename-friendly slug."""
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


class ReportGenerator:
    """Builds and outputs device log health reports."""

    STATUS_ICONS = {
        "healthy": "✅ HEALTHY",
        "stale":   "❌ STALE  ",
        "error":   "⚠️  ERROR  ",
    }

    def __init__(self, config: dict):
        self.config = config
        self.output_dir = Path(
            config.get("reporting", {}).get("output_dir", "reports")
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.csv_prefix = config.get("reporting", {}).get(
            "csv_filename_prefix", "soc_log_report"
        )

    def generate(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate results into a structured report dict.

        Returns:
            { healthy, stale, error, summary }
        """
        healthy = [r for r in results if r["status"] == "healthy"]
        stale   = [r for r in results if r["status"] == "stale"]
        error   = [r for r in results if r["status"] == "error"]

        return {
            "healthy": healthy,
            "stale":   stale,
            "error":   error,
            "summary": {
                "total":          len(results),
                "healthy_count":  len(healthy),
                "stale_count":    len(stale),
                "error_count":    len(error),
                "generated_at":   datetime.now(tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                ),
            },
        }

    def print_summary(
        self,
        report: Dict[str, Any],
        filter_siem: Optional[str] = None,
        filter_client: Optional[str] = None,
    ):
        """Print a formatted summary table to console."""
        summary = report["summary"]

        # Column widths
        col = [28, 20, 12, 17, 23, 12]
        header = (
            f"{'Device Name':<{col[0]}} "
            f"{'Client':<{col[1]}} "
            f"{'SIEM':<{col[2]}} "
            f"{'IP Address':<{col[3]}} "
            f"{'Last Log Time':<{col[4]}} "
            f"{'Status':<{col[5]}}"
        )
        width = len(header)
        divider = "─" * width
        border  = "═" * width

        # Build filter label
        scope_parts = []
        if filter_siem:
            scope_parts.append(f"SIEM={filter_siem.upper()}")
        if filter_client:
            scope_parts.append(f"Client={filter_client}")
        scope = f"  [{', '.join(scope_parts)}]" if scope_parts else ""

        print(f"\n{border}")
        print(f"  SOC LOG HEALTH REPORT — {summary['generated_at']}{scope}")
        print(border)
        print(header)
        print(divider)

        # Sort: stale → error → healthy, alphabetically within each group
        sorted_results = (
            sorted(report["stale"],   key=lambda x: (x.get("client_name") or "", x["device_name"])) +
            sorted(report["error"],   key=lambda x: (x.get("client_name") or "", x["device_name"])) +
            sorted(report["healthy"], key=lambda x: (x.get("client_name") or "", x["device_name"]))
        )

        prev_client = None
        for r in sorted_results:
            # Print client separator when client changes (nice grouping for 100+ clients)
            client = r.get("client_name") or "N/A"
            if client != prev_client:
                if prev_client is not None:
                    print(f"  {'·' * (width - 2)}")
                print(f"  ▶  {client}")
                prev_client = client

            icon = self.STATUS_ICONS.get(r["status"], r["status"])
            last_log = str(r.get("last_log_time") or "N/A")
            if len(last_log) > col[4] - 1:
                last_log = last_log[:col[4] - 1]

            print(
                f"  {str(r['device_name']):<{col[0]-2}} "
                f"{str(r.get('client_name', 'N/A')):<{col[1]}} "
                f"{str(r.get('siem_platform', '')):<{col[2]}} "
                f"{str(r.get('ip_address', '')):<{col[3]}} "
                f"{last_log:<{col[4]}} "
                f"{icon}"
            )

        print(divider)
        health_pct = (
            round(summary["healthy_count"] / summary["total"] * 100, 1)
            if summary["total"] > 0 else 0
        )
        print(
            f"  TOTAL: {summary['total']:,}  |  "
            f"✅ Healthy: {summary['healthy_count']:,} ({health_pct}%)  |  "
            f"❌ Stale: {summary['stale_count']:,}  |  "
            f"⚠️  Error: {summary['error_count']:,}"
        )
        print(f"{border}\n")

    def save_csv(
        self,
        report: Dict[str, Any],
        filter_siem: Optional[str] = None,
        filter_client: Optional[str] = None,
    ) -> Optional[Path]:
        """
        Save full results to a timestamped CSV.
        Filter context is embedded in the filename for easy identification.

        Example filenames:
          soc_log_report_20260325_103000.csv
          soc_log_report_qradar_20260325_103000.csv
          soc_log_report_qradar_acme_corp_20260325_103000.csv
        """
        all_results = report["healthy"] + report["stale"] + report["error"]
        if not all_results:
            logger.warning("No results to save to CSV.")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        parts = [self.csv_prefix]
        if filter_siem:
            parts.append(_slug(filter_siem))
        if filter_client:
            parts.append(_slug(filter_client))
        parts.append(timestamp)

        filename = self.output_dir / f"{'_'.join(parts)}.csv"

        fieldnames = [
            "device_name", "client_name", "siem_platform", "ip_address",
            "status", "last_log_time", "hours_since_last_log",
            "checked_at", "error", "notes",
        ]

        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                # Sort CSV: stale first, then error, then healthy
                ordered = (
                    sorted(report["stale"],   key=lambda x: x.get("device_name", "")) +
                    sorted(report["error"],   key=lambda x: x.get("device_name", "")) +
                    sorted(report["healthy"], key=lambda x: x.get("device_name", ""))
                )
                writer.writerows(ordered)
            logger.info(f"CSV report saved: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to save CSV: {e}")
            return None
