# SIEM Pulse — Log Source Health Monitor for QRadar, FortiSIEM & Seceon

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/abhinav7077/siem-pulse/actions/workflows/ci.yml/badge.svg)](https://github.com/abhinav7077/siem-pulse/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![SIEM: QRadar | FortiSIEM | Seceon](https://img.shields.io/badge/SIEM-QRadar%20%7C%20FortiSIEM%20%7C%20Seceon-informational.svg)](#connecting-to-real-siem-apis)
[![Roadmap](https://img.shields.io/badge/roadmap-phases-success.svg)](ROADMAP.md)

**SIEM Pulse** is an open-source Python tool for SOC analysts and MSSPs that detects **silent log sources** — firewalls, servers and other devices that have stopped sending logs to your SIEM. It checks log ingestion across **IBM QRadar**, **FortiSIEM** and **Seceon OTM** for many client environments at once, and alerts you by email or Slack when a device goes quiet.

A device that stops logging is a blind spot: attacks on it go undetected. SIEM Pulse turns a manual daily "is everything still logging?" check into an automated, scheduled SIEM health check.

> **Keywords:** SIEM log source monitoring · log ingestion health check · silent / stale log source detection · QRadar log source last event time · FortiSIEM device not reporting · SOC automation · MSSP multi-tenant monitoring · blue team tooling

---

## Features

- 📋 Reads device inventory from Excel (`.xlsx`), CSV or YAML
- 🏢 Multi-tenant: per-client SIEM endpoints and credentials, never shared across clients
- ⚡ Bulk lookups: one API call per SIEM tenant instead of one per device
- 🔎 Inventory reconciliation: finds unmonitored log sources and devices the SIEM has never seen
- 🚦 Per-tenant rate and concurrency limits
- 🔌 Modular SIEM connectors (Seceon, QRadar, FortiSIEM)
- 🕐 24-hour log staleness detection with configurable threshold
- 📊 Console summary table + CSV report output
- 📧 Email alerts (SMTP/TLS) for stale and error devices
- 💬 Slack webhook alerts (optional)
- 🔄 Retry logic with exponential backoff
- 🔐 Secure credential handling via environment variables
- 📅 Scheduled execution (run every N minutes)
- 🧪 Mock mode for testing without real SIEM credentials

---

## Project Structure

```
siem-pulse/
├── main.py                        # Run from a checkout: python main.py
├── config.yaml                    # Configuration (no secrets)
├── .env.example                   # Environment variable template
├── requirements.txt               # Python dependencies
├── sample_devices.xlsx            # Example device inventory
├── tests/                         # pytest suite (no network needed)
└── siem_pulse/
    ├── cli.py                     # Command line interface (siem-pulse)
    ├── excel_reader.py            # Reads and validates the inventory (xlsx/csv/yaml)
    ├── log_checker.py             # Checks last log time per device
    ├── report_generator.py        # Console + CSV reports
    ├── alerting.py                # Alert dispatch
    ├── reconciler.py              # Inventory vs. SIEM source comparison
    └── siem_clients/
        ├── base_client.py         # Shared HTTP, tenants, credentials, limits
        ├── factory.py             # One client per tenant
        ├── seceon_client.py       # Seceon API client
        ├── qradar_client.py       # IBM QRadar API client
        └── fortisiem_client.py    # FortiSIEM API client
```

---

## Quick Start

### 1. Clone the project

```bash
git clone https://github.com/abhinav7077/siem-pulse.git
cd siem-pulse
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
# Edit .env with your real credentials
```

Your `.env` file (never commit this):
```
SECEON_API_KEY=your_api_key
QRADAR_SEC_TOKEN=your_sec_token
FORTISIEM_USER=admin
FORTISIEM_PASS=your_password
SMTP_PASSWORD=your_smtp_password
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

The `.env` file in the current directory is loaded automatically (use `--env-file` for another path). Variables already set in your environment take priority.

### 4. Populate your device inventory

Edit `sample_devices.xlsx` (the `Devices` sheet), or use a `.csv` or `.yaml` file with the same columns:

| Column | Required | Description |
|--------|----------|-------------|
| `device_name` | ✅ | Hostname or label |
| `ip_address` | ✅ | Device IP address |
| `siem_platform` | ✅ | `seceon` / `qradar` / `fortisiem` |
| `client_name` | Optional | Client/tenant name |
| `api_endpoint` | Optional | SIEM API URL for this device's client (overrides `base_url`) |
| `auth_ref` | Optional | Client/tenant key: picks `tenants:` overrides in config and prefixed credentials (see [Multi-client setups](#multi-client-setups)) |
| `notes` | Optional | Free-text notes |

### 5. Run the monitor

```bash
# Single run (mock mode — no real API calls)
python main.py

# Single run with real APIs (set mock_mode: false in config.yaml)
python main.py

# Run on a schedule (every 60 minutes by default)
python main.py --schedule

# Use a custom device file (.xlsx, .csv or .yaml)
python main.py --device-file /path/to/my_devices.xlsx

# Compare the inventory with what the SIEMs know (unmonitored / unknown devices)
python main.py --reconcile

# Use a different config
python main.py --config /path/to/my_config.yaml
```

---

## Configuration (`config.yaml`)

Key settings you'll want to adjust:

```yaml
# Switch to false for real SIEM API calls
siem:
  mock_mode: true

# Change the staleness threshold
logic:
  threshold_hours: 24

# Enable and configure email alerts
alerting:
  email:
    enabled: true
    smtp_server: "smtp.yourcompany.com"
    sender: "soc@yourcompany.com"
    recipients:
      - "analyst@yourcompany.com"

# Run every 30 minutes instead of 60
scheduler:
  interval_minutes: 30
```

---

## Connecting to Real SIEM APIs

Every SIEM section in `config.yaml` accepts `verify_ssl: true | false | "/path/to/ca-bundle.pem"`. Keep it `true` (or point it at your internal CA) in production.

### Seceon aiSIEM / OTM
1. Log into your Seceon tenant and generate an API key
2. Set `SECEON_API_KEY` in `.env`
3. Set `siem.seceon.base_url` to your tenant URL
4. Seceon publishes its API per tenant, so the request is configurable instead of hardcoded:
   - `last_log_path` — endpoint path, may use `{ip}` and `{device_name}` (default `/devices/{ip}/lastlog`)
   - `timestamp_fields` — response fields holding the last event time; dots for nested fields (e.g. `data.last_seen`); ISO 8601 or epoch values
   - `auth_header` / `auth_scheme` — how the key is sent (default `Authorization: Bearer <key>`)

### IBM QRadar
1. Go to **Admin → Authorized Services → Add Authorized Service** and copy the **SEC token**
2. Set `QRADAR_SEC_TOKEN` in `.env` and `siem.qradar.base_url` in `config.yaml`
3. Pick a lookup mode with `siem.qradar.lookup`:
   - **`log_sources`** (default, recommended) — reads every log source and its `last_event_time` from `/config/event_sources/log_source_management/log_sources` in one paged call, cached for `log_source_cache_seconds`. A device matches when its `ip_address` equals the log source **identifier**, or its `device_name` equals the log source **name** or **identifier**.
   - **`aql`** — runs one Ariel search per device, waits for it to complete, reads the result and deletes the search. The query comes from `aql_template` (placeholders `{ip}`, `{device_name}`); by default `device_name` must equal the QRadar log source name.

### FortiSIEM
1. Ensure your FortiSIEM account has API access
2. Set `FORTISIEM_USER` and `FORTISIEM_PASS` in `.env` — on multi-tenant deployments use the `org/user` form (e.g. `super/admin`)
3. Set `siem.fortisiem.base_url` (must end in `/phoenix/rest`)
4. The client uses FortiSIEM's event query API: it submits an XML query filtered on `reptDevIpAddr` over the last `query_window_hours`, polls `/query/progress/{id}` until 100%, then reads the newest event's `phRecvTime`

### Error handling
- Timeouts, connection errors, HTTP 5xx and HTTP 429 are retried with exponential backoff (`max_retries`, `retry_delay_seconds`); a 429's `Retry-After` header is honoured up to `max_retry_after_seconds`
- Bad credentials (401/403), other 4xx responses, invalid IP addresses and unexpected response formats fail immediately with a clear error — retrying would not help

---

## Multi-client setups

For MSSPs and SOCs with many clients, each device row can point to its own SIEM tenant:

| Inventory column | Effect |
|------------------|--------|
| `api_endpoint` | Overrides that platform's `base_url` for this device |
| `auth_ref` | Loads overrides from `siem.<platform>.tenants.<auth_ref>` in `config.yaml`, and credentials from env vars prefixed with the auth_ref |

Credential naming: auth_ref `acme` reads `ACME_QRADAR_SEC_TOKEN`, `ACME_SECEON_API_KEY`, `ACME_FORTISIEM_USER` and `ACME_FORTISIEM_PASS`. Non-alphanumeric characters become `_`, so `Acme Corp-1` becomes `ACME_CORP_1_`.

**A tenant never falls back to the default credentials.** If `ACME_QRADAR_SEC_TOKEN` is missing, that tenant's devices are reported as errors and no request is sent, so one client's token is never sent to another client's SIEM.

One client object is kept per tenant (platform + api_endpoint + auth_ref). Each tenant has its own HTTP connections, bulk cache and limits:

```yaml
siem:
  qradar:
    max_concurrent_requests: 5   # parallel calls per tenant
    requests_per_second: 0       # 0 = unlimited
    tenants:
      acme:
        base_url: "https://qradar.acme.example/api"
        verify_ssl: "/etc/ssl/acme-ca.pem"
```

## Bulk lookups and reconciliation

| SIEM | Bulk mode | How |
|------|-----------|-----|
| QRadar | `lookup: log_sources` (default) | One paged log source list per tenant |
| FortiSIEM | `lookup: grouped` | One query per tenant grouped by reporting device, `MAX(phRecvTime)` |
| Seceon | `lookup: bulk` | One call to `bulk_path`, fields set by `bulk_items_field` / `bulk_ip_field` / `bulk_name_field` |

In bulk mode a 2,000-device run makes a handful of API calls instead of thousands. Bulk mode also enables `python main.py --reconcile`, which lists:

- **Unlisted sources:** the SIEM receives logs from them but they are not in your inventory, so nobody would notice if they went quiet
- **Not found:** inventory devices the SIEM has no source for (typos, wrong tenant, never onboarded)

The report prints to the console and is saved as `reports/soc_log_report_reconcile_<timestamp>.csv`.

---

## Adding a New SIEM Platform

1. Create `modules/siem_clients/my_siem_client.py` inheriting `BaseSIEMClient`
2. Implement `get_last_log_time(device) -> Optional[datetime]`. Use `self._request()` for HTTP (it handles retries, TLS, rate limits) and `self.credential("MYSIEM_TOKEN")` for secrets (it handles `auth_ref` prefixes)
3. Optional: set `supports_inventory = True` and implement `_fetch_inventory()` to get bulk lookups and `--reconcile`
4. Register it in `modules/siem_clients/factory.py`:
   ```python
   from .my_siem_client import MySIEMClient
   SIEM_REGISTRY["mysiem"] = MySIEMClient
   ```
5. Add config section under `siem:` in `config.yaml`
6. Add devices with `siem_platform: mysiem` to your inventory

---

## Output

### Console
```
════════════════════════════════════════════════════════════
  SOC LOG HEALTH REPORT — 2024-01-15 10:30:00 UTC
════════════════════════════════════════════════════════════
Device Name                    Client            SIEM         IP Address        Last Log Time          Status
───────────────────────────────────────────────────────────
db-server-01                   Acme Corp         seceon       10.10.1.20        2024-01-14 08:00 UTC   ❌ STALE
mail-gateway-01                Gamma Tech        fortisiem    172.16.5.10       N/A                    ⚠️  ERROR
web-server-01                  Acme Corp         seceon       10.10.1.10        2024-01-15 09:50 UTC   ✅ HEALTHY
...
────────────────────────────────────────────────────────────
  TOTAL: 15 | ✅ Healthy: 10 | ❌ Stale: 4 | ⚠️ Error: 1
════════════════════════════════════════════════════════════
```

### CSV Report
Saved to `reports/soc_log_report_YYYYMMDD_HHMMSS.csv` with full details.

### Email Alert
HTML-formatted email listing all stale and error devices, sent to configured recipients.

---

## Running as a Cron Job (Alternative to `--schedule`)

```bash
# Run every hour (Linux cron)
0 * * * * cd /opt/soc_monitor && /usr/bin/python3 main.py >> /var/log/soc_monitor_cron.log 2>&1
```

---

## Security Notes

- ✅ All credentials are in environment variables — never in `config.yaml`
- ✅ `.env` is gitignored — never commit it
- ✅ SSL verification configurable per SIEM in `config.yaml`
- ✅ Sensitive data is never printed to logs (only device names and IPs)
- For production: use a secrets manager (HashiCorp Vault, AWS Secrets Manager) and update the env-loading logic accordingly

---

## Roadmap

The phase-wise improvement plan — real-API fixes, multi-tenant support, smarter alerts, volume-drop detection, more SIEMs (Splunk, Sentinel, Elastic, Wazuh) and a dashboard — is in **[ROADMAP.md](ROADMAP.md)**.

---

## Running Tests

```bash
pip install pytest
python -m pytest
```

Tests use a fake HTTP layer, so they never contact a real SIEM. CI runs them on Python 3.10–3.13 for every push.

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `FileNotFoundError: sample_devices.xlsx` | Run from project root directory |
| `SECEON_API_KEY not set` | Load your `.env` file before running |
| All devices show ERROR | Ensure `mock_mode: true` in config or verify SIEM connectivity |
| `authentication/authorisation failed (HTTP 401)` | Token or password is wrong or lacks API permission — not retried |
| `Missing credentials for auth_ref 'x'` | Set the prefixed env var shown in the message (e.g. `X_QRADAR_SEC_TOKEN`) |
| QRadar device shows `Never / Not Found` | No log source identifier/name matches the device's IP or name — check the log source in QRadar |
| Email not sending | Check `SMTP_PASSWORD`, SMTP server, and port 587 access |
| `Unknown SIEM platform` | Ensure `siem_platform` column in Excel uses lowercase: `seceon`, `qradar`, `fortisiem` |

---

## Contributing

Contributions are welcome — new SIEM connectors and alert channels especially. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify and distribute this software, including commercially, under the terms of that license. See [NOTICE](NOTICE).
