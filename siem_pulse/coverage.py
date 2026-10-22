# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
coverage.py
===========
How much of each client's monitoring is actually working.

Coverage score
    Share of a client's devices that are healthy, weighted by criticality
    (critical 4, high 3, medium 2, low 1). Suppressed devices are left out.
    Degraded devices count half.

MITRE ATT&CK blind spots
    The inventory column `device_type` says what a device's logs are good for.
    Each type maps to ATT&CK data sources (names and IDs from ATT&CK v17).
    A data source is BLIND for a client when every device that provides it is
    stale or erroring — detections that rely on it cannot fire.

    Extend or override the mapping in config.yaml:

        attack:
          device_types:
            nac: ["Network Traffic", "Logon Session"]
"""

from typing import Any, Dict, List

WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}

DATA_SOURCE_IDS = {
    "Network Traffic": "DS0029",
    "Firewall": "DS0018",
    "Logon Session": "DS0028",
    "User Account": "DS0002",
    "Active Directory": "DS0026",
    "Process": "DS0009",
    "Command": "DS0017",
    "File": "DS0022",
    "Windows Registry": "DS0024",
    "Service": "DS0019",
    "Scheduled Job": "DS0003",
    "Script": "DS0012",
    "Domain Name": "DS0038",
    "Application Log": "DS0015",
    "Cloud Service": "DS0025",
    "Cloud Storage": "DS0010",
    "Instance": "DS0030",
    "Web Credential": "DS0006",
}

DEVICE_TYPES: Dict[str, List[str]] = {
    "firewall": ["Network Traffic", "Firewall"],
    "ngfw": ["Network Traffic", "Firewall", "Application Log"],
    "router": ["Network Traffic"],
    "switch": ["Network Traffic"],
    "ids": ["Network Traffic"],
    "ips": ["Network Traffic"],
    "waf": ["Network Traffic", "Application Log"],
    "proxy": ["Network Traffic", "Domain Name"],
    "vpn": ["Logon Session", "Network Traffic", "User Account"],
    "dns": ["Domain Name"],
    "domain_controller": ["Logon Session", "User Account", "Active Directory", "Process"],
    "windows_server": ["Logon Session", "Process", "Service", "Windows Registry", "Scheduled Job"],
    "windows_workstation": ["Logon Session", "Process", "Command", "Windows Registry"],
    "linux_server": ["Logon Session", "Process", "Command", "File", "Scheduled Job"],
    "edr": ["Process", "Command", "File", "Windows Registry", "Script"],
    "email_gateway": ["Application Log", "Network Traffic"],
    "identity_provider": ["Logon Session", "User Account", "Web Credential"],
    "cloud": ["Cloud Service", "Cloud Storage", "Instance", "User Account"],
    "database": ["Application Log", "Logon Session"],
    "web_server": ["Application Log", "Network Traffic"],
}

COVERED_STATUSES = ("healthy", "degraded")


def coverage_by_client(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    clients: Dict[str, Dict[str, Any]] = {}
    for r in results:
        client = r.get("client_name") or "N/A"
        entry = clients.setdefault(client, {"devices": 0, "healthy": 0, "degraded": 0, "down": 0,
                                            "suppressed": 0, "weight": 0.0, "score_weight": 0.0})
        entry["devices"] += 1
        if r.get("suppressed") and r["status"] != "healthy":
            entry["suppressed"] += 1
            continue
        weight = WEIGHTS.get(r.get("criticality") or "medium", 2)
        entry["weight"] += weight
        if r["status"] == "healthy":
            entry["healthy"] += 1
            entry["score_weight"] += weight
        elif r["status"] == "degraded":
            entry["degraded"] += 1
            entry["score_weight"] += weight / 2
        else:
            entry["down"] += 1
    for entry in clients.values():
        entry["score"] = round(100 * entry["score_weight"] / entry["weight"], 1) if entry["weight"] else 100.0
        del entry["weight"], entry["score_weight"]
    return clients


def device_type_map(config: dict) -> Dict[str, List[str]]:
    custom = ((config.get("attack") or {}).get("device_types") or {})
    return {**DEVICE_TYPES, **{str(k).lower(): list(v) for k, v in custom.items()}}


def blind_spots(results: List[Dict[str, Any]], config: dict) -> Dict[str, List[Dict[str, Any]]]:
    """{client: [{data_source, id, providers, down}]} for data sources with no working provider."""
    mapping = device_type_map(config)
    per_client: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
    for r in results:
        sources = mapping.get(str(r.get("device_type") or "").lower())
        if not sources:
            continue
        client = per_client.setdefault(r.get("client_name") or "N/A", {})
        for source in sources:
            entry = client.setdefault(source, {"working": [], "down": []})
            bucket = "working" if r["status"] in COVERED_STATUSES else "down"
            entry[bucket].append(r["device_name"])

    out: Dict[str, List[Dict[str, Any]]] = {}
    for client, sources in sorted(per_client.items()):
        blind = [
            {"data_source": name, "id": DATA_SOURCE_IDS.get(name, ""), "down": sorted(entry["down"])}
            for name, entry in sorted(sources.items())
            if entry["down"] and not entry["working"]
        ]
        if blind:
            out[client] = blind
    return out


def print_coverage(results: List[Dict[str, Any]], config: dict):
    clients = coverage_by_client(results)
    if not clients:
        return
    print("  COVERAGE BY CLIENT (criticality-weighted)")
    for client, c in sorted(clients.items(), key=lambda kv: kv[1]["score"]):
        bar = "█" * int(c["score"] // 10) + "░" * (10 - int(c["score"] // 10))
        extra = []
        if c["down"]:
            extra.append(f"{c['down']} down")
        if c["degraded"]:
            extra.append(f"{c['degraded']} degraded")
        if c["suppressed"]:
            extra.append(f"{c['suppressed']} suppressed")
        print(f"    {client[:30]:<30} {bar} {c['score']:5.1f}%  {c['devices']} devices"
              + (f"  ({', '.join(extra)})" if extra else ""))
    spots = blind_spots(results, config)
    if spots:
        print("\n  ATT&CK BLIND SPOTS (no working log source for these data sources)")
        for client, items in spots.items():
            for item in items:
                ident = f" ({item['id']})" if item["id"] else ""
                print(f"    {client[:30]:<30} {item['data_source']}{ident} — down: {', '.join(item['down'])}")
    print()
