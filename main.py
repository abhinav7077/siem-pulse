# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
SOC Log Health Monitor — main.py
=================================
Supports 2000+ devices, 100+ clients, 6+ SIEMs with:
  • Multi-threaded parallel checks (configurable thread count)
  • Filter by --siem and/or --client (run one at a time)
  • Batch processing with progress counter
  • Per-run scoped CSV reports and alerts
  • Graceful error isolation (one bad device won't stop the rest)

Usage examples:
  python main.py                                        # All devices, all SIEMs
  python main.py --siem qradar                          # Only QRadar devices
  python main.py --client "Acme Corp"                   # Only Acme Corp devices
  python main.py --siem seceon --client "Acme Corp"     # Acme Corp on Seceon only
  python main.py --threads 20                           # Use 20 parallel threads
  python main.py --schedule                             # Run every N minutes
  python main.py --list-clients                         # Show all clients in Excel
  python main.py --list-siems                           # Show all SIEMs in Excel
  python main.py --dry-run                              # Show what would run, no API calls
"""

import argparse
import logging
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

import yaml

from modules.excel_reader import ExcelReader
from modules.log_checker import LogChecker
from modules.alerting import AlertManager
from modules.report_generator import ReportGenerator
from modules.siem_clients.factory import SIEMClientFactory


# ─── Logging ──────────────────────────────────────────────────────────────────

def setup_logging(config: dict) -> logging.Logger:
    log_level = getattr(
        logging, config.get("logging", {}).get("level", "INFO").upper(), logging.INFO
    )
    log_file = config.get("logging", {}).get("file", "soc_monitor.log")

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logging.getLogger("soc_monitor")


# ─── Config ───────────────────────────────────────────────────────────────────

def load_config(config_path: str = "config.yaml") -> dict:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ─── Progress Tracker (thread-safe) ──────────────────────────────────────────

class ProgressTracker:
    """
    Thread-safe progress bar printed inline to console.
    Shows: progress bar, percentage, count, rate, and ETA.
    """

    def __init__(self, total: int):
        self.total = total
        self._done = 0
        self._lock = threading.Lock()
        self._start = datetime.now()

    def increment(self):
        with self._lock:
            self._done += 1
            elapsed = (datetime.now() - self._start).total_seconds()
            rate = self._done / elapsed if elapsed > 0 else 0
            remaining = (self.total - self._done) / rate if rate > 0 else 0
            pct = (self._done / self.total) * 100
            bar_len = 35
            filled = int(bar_len * self._done / self.total)
            bar = "█" * filled + "░" * (bar_len - filled)
            eta = (
                f"{int(remaining // 60)}m {int(remaining % 60)}s"
                if remaining > 5 else "finishing..."
            )
            print(
                f"\r  [{bar}] {pct:5.1f}%  "
                f"{self._done}/{self.total}  "
                f"| {rate:.1f} dev/s  | ETA: {eta}   ",
                end="",
                flush=True,
            )
            if self._done == self.total:
                elapsed_fmt = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
                print(f"\n  ✔  All {self.total} devices checked in {elapsed_fmt}\n")


# ─── Single device check (runs inside a thread) ───────────────────────────────

def check_one_device(
    device: Dict[str, Any],
    config: dict,
    checker: LogChecker,
    progress: ProgressTracker,
    logger: logging.Logger,
) -> Dict[str, Any]:
    """Called per thread. Checks one device and returns its result dict."""
    siem_name = device.get("siem_platform", "").lower()
    try:
        client = SIEMClientFactory.get_client(siem_name, config)
        result = checker.check_device(device, client)
    except Exception as e:
        logger.error(
            f"Unhandled error for {device.get('device_name')} "
            f"[{siem_name.upper()}]: {e}"
        )
        result = {
            **device,
            "status": "error",
            "last_log_time": None,
            "hours_since_last_log": None,
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat(),
        }
    finally:
        progress.increment()

    return result


# ─── Core Run ─────────────────────────────────────────────────────────────────

def run_check(
    config: dict,
    device_file: str,
    logger: logging.Logger,
    filter_siem: Optional[str] = None,
    filter_client: Optional[str] = None,
    num_threads: int = 10,
    dry_run: bool = False,
):
    """
    Full monitoring cycle with optional SIEM/client filtering and parallel execution.

    Filters (both optional, combinable):
        filter_siem   — e.g. 'qradar'     → only check QRadar devices
        filter_client — e.g. 'Acme Corp'  → only check Acme Corp devices

    Threading:
        num_threads — how many devices to check in parallel
        Recommended: 10-20 for stable SIEM APIs, lower if rate-limited
    """
    run_start = datetime.now()

    logger.info("=" * 70)
    logger.info("SOC Log Health Monitor — Check cycle starting")
    logger.info(f"  Time     : {run_start.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"  SIEM     : {filter_siem.upper() if filter_siem else 'ALL'}")
    logger.info(f"  Client   : {filter_client or 'ALL'}")
    logger.info(f"  Threads  : {num_threads}")
    logger.info(f"  Dry run  : {dry_run}")
    logger.info("=" * 70)

    # ── Step 1: Load inventory ────────────────────────────────────────────────
    reader = ExcelReader(device_file)
    all_devices = reader.load_devices()
    logger.info(f"Inventory total : {len(all_devices)} devices")

    # ── Step 2: Apply filters ─────────────────────────────────────────────────
    devices = all_devices

    if filter_siem:
        devices = [d for d in devices if d["siem_platform"] == filter_siem.lower()]
        logger.info(f"After SIEM filter  [{filter_siem.upper()}]     : {len(devices)} devices")

    if filter_client:
        devices = [
            d for d in devices
            if (d.get("client_name") or "").strip().lower() == filter_client.strip().lower()
        ]
        logger.info(f"After client filter [{filter_client}] : {len(devices)} devices")

    if not devices:
        logger.warning("No devices match the given filters. Nothing to do.")
        return

    # ── Step 3: Dry run — list only, no API calls ─────────────────────────────
    if dry_run:
        print(f"\n{'─' * 72}")
        print(f"  DRY RUN — {len(devices)} device(s) would be checked")
        print(f"{'─' * 72}")
        # Group by client for readability
        by_client: Dict[str, list] = {}
        for d in devices:
            key = d.get("client_name", "Unknown")
            by_client.setdefault(key, []).append(d)
        for client_name, devs in sorted(by_client.items()):
            print(f"\n  Client: {client_name} ({len(devs)} devices)")
            for d in devs:
                print(
                    f"    • {d['device_name']:<28} "
                    f"[{d['siem_platform'].upper():<10}] "
                    f"{d['ip_address']}"
                )
        print(f"\n{'─' * 72}\n")
        return

    # ── Step 4: Set up checker ────────────────────────────────────────────────
    checker = LogChecker(
        threshold_hours=config.get("logic", {}).get("threshold_hours", 24),
        max_retries=config.get("siem", {}).get("max_retries", 3),
        retry_delay=config.get("siem", {}).get("retry_delay_seconds", 5),
    )

    # ── Step 5: Parallel device checks ───────────────────────────────────────
    results: List[Dict[str, Any]] = []
    progress = ProgressTracker(total=len(devices))
    effective_threads = min(num_threads, len(devices))

    logger.info(
        f"Starting parallel check: {len(devices)} devices | "
        f"{effective_threads} threads"
    )
    print()  # Space before progress bar

    with ThreadPoolExecutor(
        max_workers=effective_threads, thread_name_prefix="soc_worker"
    ) as executor:
        futures = {
            executor.submit(
                check_one_device, device, config, checker, progress, logger
            ): device
            for device in devices
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                device = futures[future]
                logger.error(f"Thread exception for {device.get('device_name')}: {e}")

    # ── Step 6: Report ────────────────────────────────────────────────────────
    reporter = ReportGenerator(config)
    report = reporter.generate(results)
    reporter.print_summary(
        report, filter_siem=filter_siem, filter_client=filter_client
    )
    reporter.save_csv(
        report, filter_siem=filter_siem, filter_client=filter_client
    )

    # ── Step 7: Alerts ────────────────────────────────────────────────────────
    stale = [r for r in results if r["status"] == "stale"]
    errors = [r for r in results if r["status"] == "error"]

    if stale or errors:
        alerter = AlertManager(config)
        alerter.send_alert(
            stale, errors,
            filter_siem=filter_siem, filter_client=filter_client
        )
    else:
        logger.info("All checked devices healthy — no alerts sent.")

    # ── Timing ────────────────────────────────────────────────────────────────
    elapsed = (datetime.now() - run_start).total_seconds()
    rate = len(devices) / elapsed if elapsed > 0 else 0
    logger.info(
        f"Cycle done | {len(devices)} devices | "
        f"{elapsed:.1f}s | {rate:.1f} devices/sec | "
        f"Stale: {len(stale)} | Errors: {len(errors)}"
    )
    logger.info("=" * 70)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SOC Log Health Monitor — multi-SIEM, multi-client log checker",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                                 # Check all devices\n"
            "  python main.py --siem qradar                  # QRadar only\n"
            "  python main.py --client \"Acme Corp\"            # Acme only\n"
            "  python main.py --siem seceon --client \"Acme\"   # Combined filter\n"
            "  python main.py --list-clients                  # Show all clients\n"
            "  python main.py --dry-run --siem fortisiem      # Preview only\n"
        ),
    )

    parser.add_argument("--config",       default="config.yaml",    help="Config YAML path")
    parser.add_argument("--device-file",  default=None,             help="Excel device inventory path")
    parser.add_argument("--siem",         default=None,             help="Filter by SIEM platform (e.g. qradar)")
    parser.add_argument("--client",       default=None,             help="Filter by client name (e.g. 'Acme Corp')")
    parser.add_argument("--threads",      type=int, default=None,   help="Number of parallel threads (default: from config)")
    parser.add_argument("--schedule",     action="store_true",      help="Run repeatedly on schedule")
    parser.add_argument("--dry-run",      action="store_true",      help="Preview devices without API calls")
    parser.add_argument("--list-clients", action="store_true",      help="List all clients in inventory and exit")
    parser.add_argument("--list-siems",   action="store_true",      help="List all SIEM platforms in inventory and exit")

    args = parser.parse_args()
    config = load_config(args.config)
    logger = setup_logging(config)

    device_file = args.device_file or config.get("devices", {}).get("file", "sample_devices.xlsx")
    num_threads = args.threads or config.get("performance", {}).get("threads", 10)

    # ── Discovery helpers (list and exit) ──────────────────────────────────────
    if args.list_clients or args.list_siems:
        reader = ExcelReader(device_file)
        devices = reader.load_devices()

        if args.list_clients:
            clients = sorted(set(d.get("client_name", "N/A") or "N/A" for d in devices))
            print(f"\n{'─'*50}")
            print(f"  {len(clients)} client(s) found in {device_file}")
            print(f"{'─'*50}")
            for c in clients:
                count = sum(1 for d in devices if (d.get("client_name") or "N/A") == c)
                siems = sorted(set(
                    d["siem_platform"] for d in devices
                    if (d.get("client_name") or "N/A") == c
                ))
                print(f"  {c:<35} {count:>4} devices   SIEMs: {', '.join(siems)}")
            print()

        if args.list_siems:
            siems = sorted(set(d.get("siem_platform", "N/A") for d in devices))
            print(f"\n{'─'*50}")
            print(f"  {len(siems)} SIEM platform(s) found in {device_file}")
            print(f"{'─'*50}")
            for s in siems:
                count = sum(1 for d in devices if d.get("siem_platform") == s)
                clients_on_siem = sorted(set(
                    d.get("client_name", "N/A") or "N/A"
                    for d in devices if d.get("siem_platform") == s
                ))
                print(f"  {s.upper():<15} {count:>4} devices   Clients: {len(clients_on_siem)}")
            print()
        return

    # ── Build run kwargs ───────────────────────────────────────────────────────
    run_kwargs = dict(
        config=config,
        device_file=device_file,
        logger=logger,
        filter_siem=args.siem,
        filter_client=args.client,
        num_threads=num_threads,
        dry_run=args.dry_run,
    )

    # ── Schedule or single run ─────────────────────────────────────────────────
    if args.schedule:
        try:
            import schedule as sched
        except ImportError:
            logger.error("'schedule' package not installed. Run: pip install schedule")
            sys.exit(1)

        interval = config.get("scheduler", {}).get("interval_minutes", 60)
        logger.info(f"Scheduler mode — every {interval} minute(s)")
        sched.every(interval).minutes.do(run_check, **run_kwargs)
        run_check(**run_kwargs)       # Run immediately on launch
        while True:
            sched.run_pending()
            time.sleep(30)
    else:
        run_check(**run_kwargs)


if __name__ == "__main__":
    main()
