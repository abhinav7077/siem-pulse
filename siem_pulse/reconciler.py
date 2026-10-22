# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
reconciler.py
=============
Compares the device inventory with what each SIEM tenant actually knows.

For every tenant (platform + api_endpoint + auth_ref) whose client can list
its sources, it reports:
    unlisted   — sources the SIEM receives logs from that are NOT in the
                 inventory (unmonitored devices: nobody notices if they go quiet)
    not_found  — inventory devices the SIEM has no source for (typo in the
                 inventory, wrong tenant, or the device was never onboarded)

Matching uses the same rules as device checks: IP equals the source
identifier, or device name equals the source name or identifier.
"""

import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .siem_clients.base_client import SIEMError
from .siem_clients.factory import SIEMClientFactory

logger = logging.getLogger(__name__)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def reconcile(devices: List[Dict[str, Any]], config: dict) -> Dict[str, Any]:
    """Return {"unlisted": [...], "not_found": [...], "skipped": [...], "errors": [...]}."""
    groups: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for device in devices:
        groups.setdefault(SIEMClientFactory.tenant_key(device), []).append(device)

    result = {"unlisted": [], "not_found": [], "skipped": [], "errors": []}

    for _key, tenant_devices in sorted(groups.items()):
        client = SIEMClientFactory.get_client_for_device(tenant_devices[0], config)
        tenant = client.tenant_label
        clients = ", ".join(sorted({d.get("client_name") or "N/A" for d in tenant_devices}))

        if not client.supports_inventory:
            mode = getattr(client, "inventory_lookup_mode", None)
            reason = "this lookup mode cannot list sources"
            if mode:
                reason += f" — set siem.{client.config_key}.lookup: {mode} to enable"
            result["skipped"].append({"tenant": tenant, "clients": clients, "reason": reason})
            continue
        try:
            sources = list(client.list_known_sources())
        except SIEMError as e:
            logger.error(f"Reconcile failed for {tenant}: {e}")
            result["errors"].append({"tenant": tenant, "clients": clients, "error": str(e)})
            continue

        if client.mock_mode:
            # Mock inventories cannot know the real devices; treat them as present
            sources += [{"name": d["device_name"], "identifier": d["ip_address"],
                         "last_seen": None} for d in tenant_devices]

        # Index both sides so large tenants stay fast
        device_ips = {_norm(d.get("ip_address")) for d in tenant_devices}
        device_names = {_norm(d.get("device_name")) for d in tenant_devices}
        source_identifiers = {_norm(s.get("identifier")) for s in sources}
        source_keys = source_identifiers | {_norm(s.get("name")) for s in sources}

        for source in sources:
            identifier, name = _norm(source.get("identifier")), _norm(source.get("name"))
            if identifier not in device_ips and not ({identifier, name} & device_names):
                last_seen = source.get("last_seen")
                result["unlisted"].append({
                    "tenant": tenant, "clients": clients,
                    "name": source.get("name") or "", "identifier": source.get("identifier") or "",
                    "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if last_seen else "",
                })

        for device in tenant_devices:
            ip, name = _norm(device.get("ip_address")), _norm(device.get("device_name"))
            if ip not in source_identifiers and name not in source_keys:
                result["not_found"].append({
                    "tenant": tenant, "clients": device.get("client_name") or "N/A",
                    "name": device["device_name"], "identifier": device["ip_address"],
                    "last_seen": "",
                })

    return result


def print_reconcile(result: Dict[str, Any]):
    width = 100
    print(f"\n{'═' * width}\n  INVENTORY RECONCILIATION\n{'═' * width}")
    sections = [
        ("unlisted", "Sources in the SIEM but NOT in the inventory (unmonitored)"),
        ("not_found", "Inventory devices the SIEM has no source for"),
    ]
    for key, title in sections:
        rows = result[key]
        print(f"\n  {title}: {len(rows)}")
        for r in rows:
            print(f"    • {r['name'][:32]:<32} {r['identifier'][:22]:<22} {r['tenant']:<22} {r['clients']}")
    for r in result["skipped"]:
        print(f"\n  ⏭  Skipped {r['tenant']} ({r['clients']}): {r['reason']}")
    for r in result["errors"]:
        print(f"\n  ⚠️  {r['tenant']} ({r['clients']}): {r['error']}")
    print(f"\n{'═' * width}\n")


def save_reconcile_csv(result: Dict[str, Any], config: dict) -> Path:
    reporting = config.get("reporting", {})
    output_dir = Path(reporting.get("output_dir", "reports"))
    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = reporting.get("csv_filename_prefix", "soc_log_report")
    path = output_dir / f"{prefix}_reconcile_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["finding", "tenant", "clients", "name", "identifier", "last_seen"]
        )
        writer.writeheader()
        for finding in ("unlisted", "not_found"):
            for row in result[finding]:
                writer.writerow({"finding": finding, **row})
    logger.info(f"Reconciliation report saved: {path}")
    return path
