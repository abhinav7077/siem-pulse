# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
SIEM Pulse — command line interface
====================================
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
  python main.py --reconcile                            # Compare inventory with SIEM sources
"""

import argparse
import logging
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import yaml

from siem_pulse import __version__

from siem_pulse.inventory_sources import load_inventory
from siem_pulse.alert_policy import classify, digest_batch, digest_due
from siem_pulse.coverage import print_coverage
from siem_pulse.detection import run_detection
from siem_pulse.ops import JsonFormatter, check_heartbeat, ping_heartbeat, write_metrics_textfile
from siem_pulse.log_checker import LogChecker, device_key
from siem_pulse.state_store import StateStore, to_iso
from siem_pulse.suppression import apply_suppression, matches, parse_until
from siem_pulse.alerting import AlertManager
from siem_pulse.reconciler import print_reconcile, reconcile, save_reconcile_csv
from siem_pulse.report_generator import ReportGenerator
from siem_pulse.siem_clients.factory import SIEMClientFactory


# ─── Logging ──────────────────────────────────────────────────────────────────

def setup_logging(config: dict) -> logging.Logger:
    log_level = getattr(
        logging, config.get("logging", {}).get("level", "INFO").upper(), logging.INFO
    )
    log_file = config.get("logging", {}).get("file", "soc_monitor.log")

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    if str(config.get("logging", {}).get("format", "text")).lower() == "json":
        for handler in handlers:
            handler.setFormatter(JsonFormatter())

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logging.getLogger("soc_monitor")


# ─── Environment ──────────────────────────────────────────────────────────────

def load_env_file(path: str = ".env") -> bool:
    """
    Load secrets from a .env file if it exists. Variables already set in the
    environment win. Returns True when a file was loaded.
    """
    if not path or not Path(path).is_file():
        return False
    try:
        from dotenv import load_dotenv
    except ImportError:
        logging.getLogger("soc_monitor").warning(
            f"{path} found but python-dotenv is not installed: pip install python-dotenv"
        )
        return False
    return bool(load_dotenv(path, override=False))


# ─── Config ───────────────────────────────────────────────────────────────────

def load_config(config_path: str = "config.yaml") -> dict:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(path, "r") as f:
        return yaml.safe_load(f)


def sheet_name(config: dict) -> str:
    """Excel sheet holding the device inventory (config: devices.sheet_name)."""
    return config.get("devices", {}).get("sheet_name") or "Devices"


def resolve_beside_config(path: str, config_path: str) -> str:
    """A relative inventory path that is not in the working directory is looked up next to the config."""
    candidate = Path(path)
    if candidate.is_absolute() or candidate.exists():
        return path
    beside = Path(config_path).resolve().parent / candidate
    return str(beside) if beside.exists() else path


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
        # Draw the bar only on a terminal; in cron/docker logs print every 10% instead
        self.interactive = sys.stdout.isatty()
        self._next_report = 10

    def increment(self):
        with self._lock:
            self._done += 1
            elapsed = (datetime.now() - self._start).total_seconds()
            rate = self._done / elapsed if elapsed > 0 else 0
            remaining = (self.total - self._done) / rate if rate > 0 else 0
            pct = (self._done / self.total) * 100
            if not self.interactive:
                if pct >= self._next_report or self._done == self.total:
                    print(f"  progress: {self._done}/{self.total} devices ({pct:.0f}%)", flush=True)
                    self._next_report = (int(pct) // 10 + 1) * 10
                return
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
        client = SIEMClientFactory.get_client_for_device(device, config)
        result = checker.check_device(device, client)
    except Exception as e:
        logger.error(
            f"Unhandled error for {device.get('device_name')} "
            f"[{siem_name.upper()}]: {e}"
        )
        result = {
            **device,
            "device_key": device_key(device),
            "client_name": device.get("client_name") or "N/A",
            "criticality": device.get("criticality") or "medium",
            "threshold_hours": checker.threshold_for(device),
            "status": "error",
            "last_log_time": None,
            "hours_since_last_log": None,
            "error": str(e),
            "checked_at": datetime.now(tz=timezone.utc).isoformat(),
        }
    finally:
        progress.increment()

    return result


# ─── Inventory ────────────────────────────────────────────────────────────────

def load_filtered_devices(
    config: dict,
    device_file: str,
    logger: logging.Logger,
    filter_siem: Optional[str] = None,
    filter_client: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load the inventory and apply the optional --siem / --client filters."""
    devices = load_inventory(config, device_file, sheet_name(config))
    logger.info(f"Inventory total : {len(devices)} devices")

    if filter_siem:
        devices = [d for d in devices if d["siem_platform"] == filter_siem.lower()]
        logger.info(f"After SIEM filter  [{filter_siem.upper()}]     : {len(devices)} devices")

    if filter_client:
        devices = [
            d for d in devices
            if (d.get("client_name") or "").strip().lower() == filter_client.strip().lower()
        ]
        logger.info(f"After client filter [{filter_client}] : {len(devices)} devices")
    return devices


def run_reconcile(
    config: dict,
    device_file: str,
    logger: logging.Logger,
    filter_siem: Optional[str] = None,
    filter_client: Optional[str] = None,
):
    """Compare the inventory with the sources each SIEM tenant knows about."""
    devices = load_filtered_devices(config, device_file, logger, filter_siem, filter_client)
    if not devices:
        logger.warning("No devices match the given filters. Nothing to reconcile.")
        return
    if filter_client:
        logger.warning(
            "Reconciling with --client: if this client shares a SIEM tenant with other "
            "clients, their devices will be reported as 'unlisted'."
        )
    result = reconcile(devices, config)
    print_reconcile(result)
    save_reconcile_csv(result, config)


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

    # ── Steps 1–2: Load inventory and apply filters ───────────────────────────
    devices = load_filtered_devices(config, device_file, logger, filter_siem, filter_client)
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
        criticality_thresholds=config.get("logic", {}).get("criticality_thresholds"),
        max_retries=config.get("siem", {}).get("max_retries", 3),
        retry_delay=config.get("siem", {}).get("retry_delay_seconds", 5),
        max_retry_after=config.get("siem", {}).get("max_retry_after_seconds", 300),
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

    # ── Step 6: History, suppression, detection ──────────────────────────────
    scope = AlertManager._scope_label(filter_siem, filter_client)
    store = StateStore.from_config(config)
    run_id = store.start_run(scope)
    previous = store.get_states(r["device_key"] for r in results)
    suppressed = apply_suppression(results, config, store.active_snoozes())
    if suppressed:
        logger.info(f"{suppressed} device(s) suppressed (snooze / maintenance) — reported, not alerted")
    run_post_check_hooks(results, config, store)

    # ── Step 7: Report ────────────────────────────────────────────────────────
    reporter = ReportGenerator(config)
    report = reporter.generate(results)
    reporter.print_summary(
        report, filter_siem=filter_siem, filter_client=filter_client
    )
    reporter.save_csv(
        report, filter_siem=filter_siem, filter_client=filter_client
    )
    if config.get("reporting", {}).get("show_coverage", True):
        print_coverage(results, config)

    # ── Step 8: Alerts on what changed ────────────────────────────────────────
    batch = classify(results, previous, config, scope=scope)
    store.update_states(results, previous)
    alerter = AlertManager(config, store)
    alerter.dispatch(batch)
    maybe_send_digest(config, store, alerter, logger)

    # ── Timing ────────────────────────────────────────────────────────────────
    elapsed = (datetime.now() - run_start).total_seconds()
    store.finish_run(run_id, results, elapsed)
    rate = len(devices) / elapsed if elapsed > 0 else 0
    stale = sum(1 for r in results if r["status"] == "stale")
    errors = sum(1 for r in results if r["status"] == "error")
    degraded = sum(1 for r in results if r["status"] == "degraded")
    logger.info(
        f"Cycle done | {len(devices)} devices | "
        f"{elapsed:.1f}s | {rate:.1f} devices/sec | "
        f"Stale: {stale} | Errors: {errors} | Degraded: {degraded} | Suppressed: {suppressed}"
    )
    logger.info("=" * 70)
    run_after_run_hooks(config, store, results, elapsed)
    store.close()
    return {"run_id": run_id, "results": results, "batch": batch}


# ─── Hooks filled in by later phases ─────────────────────────────────────────

def run_post_check_hooks(results: List[Dict[str, Any]], config: dict, store: StateStore):
    """Extra checks on the results before reporting (deeper detection)."""
    try:
        run_detection(results, config, store)
    except Exception as e:  # detection must never stop the main check
        logging.getLogger("soc_monitor").error(f"Detection failed, continuing without it: {e}")


def run_after_run_hooks(config: dict, store: StateStore, results: List[Dict[str, Any]], elapsed: float):
    """Things to do once a run is recorded (metrics export, heartbeat)."""
    log = logging.getLogger("soc_monitor")
    try:
        path = write_metrics_textfile(config, store)
        if path:
            log.info(f"Prometheus metrics written to {path}")
    except OSError as e:
        log.error(f"Could not write metrics textfile: {e}")
    ping_heartbeat(config)


# ─── Digest and snoozes ───────────────────────────────────────────────────────

def maybe_send_digest(config: dict, store: StateStore, alerter: AlertManager, logger: logging.Logger,
                      force: bool = False) -> bool:
    if not force and not digest_due(config, store.get_meta("last_digest_at")):
        return False
    batch = digest_batch(store.open_issues())
    if batch.is_empty():
        logger.info("Digest: no open issues.")
    else:
        alerter.dispatch(batch)
    store.set_meta("last_digest_at", to_iso(datetime.now(tz=timezone.utc)))
    return True


def find_devices(devices: List[Dict[str, Any]], pattern: str) -> List[Dict[str, Any]]:
    """Devices whose name or IP matches `pattern` (glob, case-insensitive)."""
    return [d for d in devices
            if matches(d, {"device_name": pattern}) or matches(d, {"ip_address": pattern})]


def run_snooze_command(args, config: dict, device_file: str, logger: logging.Logger):
    store = StateStore.from_config(config)
    try:
        if args.list_snoozes:
            snoozes = store.active_snoozes()
            print(f"\n  {len(snoozes)} active snooze(s)")
            for s in sorted(snoozes.values(), key=lambda x: x["until"]):
                until = s["until"][:16].replace("T", " ")
                print(f"    • {s['device_name']:<30} until {until} UTC  {s['reason'] or ''}")
            print()
            return
        pattern = args.snooze or args.unsnooze
        targets = find_devices(load_filtered_devices(config, device_file, logger, args.siem, args.client), pattern)
        if not targets:
            logger.error(f"No device in the inventory matches '{pattern}'")
            sys.exit(1)
        for d in targets:
            key = device_key(d)
            if args.snooze:
                until = parse_until(args.until or "24h")
                store.snooze(key, d["device_name"], until, args.reason or "")
                print(f"  🔕 {d['device_name']} snoozed until {until.strftime('%Y-%m-%d %H:%M UTC')}")
            else:
                done = store.unsnooze(key)
                print(f"  🔔 {d['device_name']} {'unsnoozed' if done else 'was not snoozed'}")
    finally:
        store.close()


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
            "  python main.py --reconcile                     # Unmonitored / unknown devices\n"
        ),
    )

    parser.add_argument("--version",      action="version",         version=f"siem-pulse {__version__}")
    parser.add_argument("--config",       default="config.yaml",    help="Config YAML path")
    parser.add_argument("--env-file",     default=".env",
                        help="Env file with secrets (default: .env, if present)")
    parser.add_argument("--device-file",  default=None,             help="Excel device inventory path")
    parser.add_argument("--siem",         default=None,             help="Filter by SIEM platform (e.g. qradar)")
    parser.add_argument("--client",       default=None,             help="Filter by client name (e.g. 'Acme Corp')")
    parser.add_argument("--threads",      type=int, default=None,
                        help="Number of parallel threads (default: from config)")
    parser.add_argument("--schedule",     action="store_true",      help="Run repeatedly on schedule")
    parser.add_argument("--dry-run",      action="store_true",      help="Preview devices without API calls")
    parser.add_argument("--list-clients", action="store_true",      help="List all clients in inventory and exit")
    parser.add_argument("--list-siems",   action="store_true",
                        help="List all SIEM platforms in inventory and exit")
    parser.add_argument("--snooze",       metavar="DEVICE",
                        help="Snooze alerts for a device (name or IP, * wildcards allowed)")
    parser.add_argument("--until",        metavar="WHEN",
                        help="With --snooze: 4h, 2d or 2026-10-25T08:00 (default 24h)")
    parser.add_argument("--reason",       help="With --snooze: why (shown in reports)")
    parser.add_argument("--unsnooze",     metavar="DEVICE", help="Remove a snooze")
    parser.add_argument("--list-snoozes", action="store_true", help="Show active snoozes")
    parser.add_argument("--digest",       action="store_true",
                        help="Send the open-issues digest now (no SIEM calls)")
    parser.add_argument("--dashboard",    action="store_true",
                        help="Serve the web dashboard (with --schedule: alongside the checks)")
    parser.add_argument("--host",         default=None, help="Dashboard address (default: dashboard.host)")
    parser.add_argument("--port",         type=int, default=None, help="Dashboard port (default: dashboard.port)")
    parser.add_argument("--check-heartbeat", action="store_true",
                        help="Alert and exit 2 if no run finished recently (run from a separate cron)")
    parser.add_argument("--reconcile",    action="store_true",
                        help="Compare inventory with sources the SIEMs know, then exit")

    args = parser.parse_args()
    load_env_file(args.env_file)
    config = load_config(args.config)
    logger = setup_logging(config)

    device_file = args.device_file or resolve_beside_config(
        config.get("devices", {}).get("file", "sample_devices.xlsx"), args.config
    )
    num_threads = args.threads or config.get("performance", {}).get("threads", 10)

    # ── Discovery helpers (list and exit) ──────────────────────────────────────
    if args.list_clients or args.list_siems:
        devices = load_inventory(config, device_file, sheet_name(config))

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

    # ── Snoozes and digest (no SIEM calls) ─────────────────────────────────────
    if args.snooze or args.unsnooze or args.list_snoozes:
        run_snooze_command(args, config, device_file, logger)
        return
    if args.check_heartbeat:
        store = StateStore.from_config(config)
        healthy = check_heartbeat(config, store, AlertManager(config, store))
        store.close()
        print("  heartbeat ok" if healthy else "  heartbeat STALE — alert sent")
        sys.exit(0 if healthy else 2)
    if args.digest:
        store = StateStore.from_config(config)
        maybe_send_digest(config, store, AlertManager(config, store), logger, force=True)
        store.close()
        return

    # ── Reconciliation (report and exit) ───────────────────────────────────────
    if args.reconcile:
        run_reconcile(config, device_file, logger, args.siem, args.client)
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

    # ── Dashboard / schedule / single run ──────────────────────────────────────
    if args.dashboard and not args.schedule:
        from siem_pulse.dashboard import serve
        serve(config, args.host, args.port)
        return

    if args.schedule:
        try:
            import schedule as sched
        except ImportError:
            logger.error("'schedule' package not installed. Run: pip install schedule")
            sys.exit(1)

        if args.dashboard:
            from siem_pulse.dashboard import serve
            serve(config, args.host, args.port, background=True)

        def safe_run():
            # One failed cycle (network down, bad file) must not stop the scheduler
            try:
                run_check(**run_kwargs)
            except Exception as e:
                logger.exception(f"Check cycle failed: {e}")
                ping_heartbeat(config, failed=True)

        interval = config.get("scheduler", {}).get("interval_minutes", 60)
        logger.info(f"Scheduler mode — every {interval} minute(s)")
        sched.every(interval).minutes.do(safe_run)
        safe_run()                    # Run immediately on launch
        while True:
            sched.run_pending()
            time.sleep(30)
    else:
        try:
            run_check(**run_kwargs)
        except Exception:
            ping_heartbeat(config, failed=True)
            raise


if __name__ == "__main__":
    main()
