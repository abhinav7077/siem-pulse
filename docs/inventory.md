# Inventory

The inventory lists every device SIEM Pulse should watch. It can be an Excel file, CSV, YAML, or a ServiceNow CMDB table.

## Columns

| Column | Required | Description |
|--------|----------|-------------|
| `device_name` | ✅ | Hostname or label |
| `ip_address` | ✅ | Device IP address |
| `siem_platform` | ✅ | `qradar`, `splunk`, `sentinel`, `elastic`, `fortisiem`, `wazuh`, `sumologic`, `seceon`, `generic_rest` or a plugin name |
| `client_name` | | Client / tenant (used for routing, dashboards, coverage) |
| `api_endpoint` | | This client's SIEM API URL (overrides `base_url`) |
| `auth_ref` | | Tenant key: config overrides and prefixed credentials — see [Multi-client](multi-tenant.md) |
| `criticality` | | `critical` / `high` / `medium` / `low` — threshold and routing |
| `threshold_hours` | | Hours without logs before the device is stale (wins over everything) |
| `snooze_until` | | No alerts until this date/time |
| `device_type` | | e.g. `firewall`, `domain_controller`, `edr` — for [ATT&CK coverage](detection.md#mitre-attck-blind-spots) |
| `expected_log_types` | | e.g. `traffic;system` — for [missing log type](detection.md) checks |
| `min_events_per_hour` | | Alert when volume drops below this |
| `notes` | | Free text, shown in tickets |

Rows with a missing required value or an unknown platform are skipped with a warning; invalid optional values are ignored with a warning.

## File formats

```yaml
# devices.yaml
devices:
  - {device_name: fw-edge-01, ip_address: 10.0.0.1, siem_platform: qradar, client_name: Acme Corp,
     criticality: critical, device_type: firewall, expected_log_types: "traffic;system"}
```

```csv
device_name,ip_address,siem_platform,client_name,criticality,device_type
fw-edge-01,10.0.0.1,qradar,Acme Corp,critical,firewall
```

Set the path with `devices.file` (or `--device-file`). Excel files read the `devices.sheet_name` sheet. A relative path that is not in the working directory is also looked up next to `config.yaml`.

## ServiceNow CMDB

```yaml
devices:
  source: servicenow
  servicenow:
    instance_url: "https://acme.service-now.com"
    table: cmdb_ci_netgear
    query: "operational_status=1^u_siem_platformISNOTEMPTY"
    field_map: {device_name: name, ip_address: ip_address, siem_platform: u_siem_platform,
                client_name: company, criticality: u_criticality}
    defaults: {siem_platform: qradar}
```

Credentials: `SERVICENOW_USER` / `SERVICENOW_PASS`. Reference fields such as `company` are read as display values.

## Keeping it honest

Run `siem-pulse --reconcile` regularly. It lists sources the SIEM receives logs from that are **not** in the inventory (nobody would notice if they went quiet) and inventory devices the SIEM has **never** seen (typos, wrong tenant, never onboarded).
