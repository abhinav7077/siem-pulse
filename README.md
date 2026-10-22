# SIEM Pulse — Log Source Health Monitor for QRadar, Splunk, Sentinel, Elastic, FortiSIEM & more

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/abhinav7077/siem-pulse/actions/workflows/ci.yml/badge.svg)](https://github.com/abhinav7077/siem-pulse/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![SIEMs: 9 connectors](https://img.shields.io/badge/SIEM-QRadar%20%7C%20Splunk%20%7C%20Sentinel%20%7C%20Elastic%20%7C%20FortiSIEM%20%7C%20Wazuh-informational.svg)](#supported-siems)
[![PyPI](https://img.shields.io/pypi/v/siem-pulse.svg)](https://pypi.org/project/siem-pulse/)
[![Docs](https://img.shields.io/badge/docs-abhinav7077.github.io%2Fsiem--pulse-blue.svg)](https://abhinav7077.github.io/siem-pulse/)
[![Container](https://img.shields.io/badge/container-ghcr.io-informational.svg)](https://github.com/abhinav7077/siem-pulse/pkgs/container/siem-pulse)
[![Roadmap](https://img.shields.io/badge/roadmap-phases-success.svg)](ROADMAP.md)

**SIEM Pulse** is an open-source Python tool for SOC analysts and MSSPs that detects **silent log sources** — firewalls, servers and other devices that have stopped sending logs to your SIEM. It checks log ingestion across **IBM QRadar**, **Splunk**, **Microsoft Sentinel**, **Elastic**, **FortiSIEM**, **Wazuh**, **Sumo Logic** and **Seceon** — or any platform with a REST API — for many client environments at once, and alerts you by email, Slack, Teams, PagerDuty, Opsgenie, ServiceNow or Jira when a device goes quiet.

A device that stops logging is a blind spot: attacks on it go undetected. SIEM Pulse turns a manual daily "is everything still logging?" check into an automated, scheduled SIEM health check.

📖 **Documentation:** <https://abhinav7077.github.io/siem-pulse/> — setup guides for every SIEM, alerting, detection and deployment.

![SIEM Pulse dashboard: devices, coverage per client, open issues and ATT&CK blind spots](docs/assets/dashboard.png)

> **Keywords:** SIEM log source monitoring · log ingestion health check · silent / stale log source detection · QRadar log source last event time · FortiSIEM device not reporting · SOC automation · MSSP multi-tenant monitoring · blue team tooling

---

## Features

- 📋 Reads device inventory from Excel (`.xlsx`), CSV or YAML
- 🏢 Multi-tenant: per-client SIEM endpoints and credentials, never shared across clients
- ⚡ Bulk lookups: one API call per SIEM tenant instead of one per device
- 🔎 Inventory reconciliation: finds unmonitored log sources and devices the SIEM has never seen
- 🚦 Per-tenant rate and concurrency limits
- 🔌 SIEM connectors: QRadar, Splunk, Microsoft Sentinel, Elastic, FortiSIEM, Wazuh, Sumo Logic, Seceon, plus a configurable generic REST connector and pip-installable plugins
- 🕐 24-hour log staleness detection with configurable threshold
- 📊 Console summary table + CSV report output
- 🔔 Alerts on **changes only**: new issue, still open (reminder), recovered — with run history in SQLite
- 🎯 Per-device thresholds and criticality, snoozes and maintenance windows
- 📬 Channels: email (HTML + text), Slack, Microsoft Teams, PagerDuty, Opsgenie, ServiceNow, Jira, generic webhook (SOAR)
- 🧭 Routing per client / criticality, plus a daily digest
- 📉 Deeper detection: volume drops vs a 7-day baseline, missing log types, unparsed events, clock skew
- 🗺️ Coverage score per client and MITRE ATT&CK data-source blind spots
- 🖥️ Built-in web dashboard with per-client access, Prometheus `/metrics`, `/healthz` and a Grafana dashboard
- 🐳 Docker image, Compose, Helm chart, Kubernetes CronJob and systemd timers; JSON logs and heartbeat pings
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
├── sample_devices.xlsx            # Example device inventory
├── Dockerfile, docker-compose.yml # Container image and Compose setup
├── deploy/                        # Helm chart, Kubernetes, systemd, Grafana
├── docs/                          # Documentation site (MkDocs)
├── tests/                         # pytest suite (no network needed)
└── siem_pulse/
    ├── cli.py                     # Command line interface (siem-pulse)
    ├── excel_reader.py            # Inventory files (xlsx / csv / yaml)
    ├── inventory_sources.py       # ServiceNow CMDB inventory
    ├── credentials.py             # Secrets providers (env, Vault, AWS, Azure)
    ├── log_checker.py             # Last-seen check and thresholds
    ├── detection.py               # Volume, log type, parsing and clock-skew checks
    ├── coverage.py                # Coverage score and ATT&CK blind spots
    ├── state_store.py             # SQLite run history
    ├── suppression.py             # Snoozes and maintenance windows
    ├── alert_policy.py            # New / reminder / recovered, routing, digest
    ├── alerting.py                # Sends batches to channels
    ├── channels/                  # email, Slack, Teams, webhook, PagerDuty, Opsgenie, ServiceNow, Jira
    ├── reconciler.py              # Inventory vs. SIEM sources
    ├── report_generator.py        # Console + CSV reports
    ├── dashboard.py               # Web dashboard, API, Prometheus metrics
    ├── ops.py                     # JSON logs, heartbeat, metrics textfile
    ├── templates/                 # Files written by `siem-pulse --init`
    └── siem_clients/              # One module per SIEM + shared base and factory
```

## Quick Start

### 1. Install

```bash
pip install siem-pulse                 # Python 3.10+
mkdir siem-pulse && cd siem-pulse
siem-pulse --init                      # starter config.yaml, .env.example, sample_devices.xlsx
```

Or with Docker: `docker compose up -d` (see [Deploy](#deploy)). Or from source: `git clone https://github.com/abhinav7077/siem-pulse.git && cd siem-pulse && pip install -e ".[dev]"` and use `python main.py` instead of `siem-pulse`.

### 2. Try it in mock mode

The starter config has `siem.mock_mode: true`, so everything works without a SIEM:

```bash
siem-pulse --dry-run          # which devices would be checked
siem-pulse                    # one check: console table, CSV report, alerts, history
siem-pulse --reconcile        # inventory vs. what the SIEM knows
siem-pulse --dashboard        # http://127.0.0.1:8080
```

### 3. Configure credentials

```bash
cp .env.example .env          # add the credentials for your SIEM(s) and alert channels
```

The `.env` file in the current directory is loaded automatically (use `--env-file` for another path). Variables already set in your environment take priority. Never commit `.env`.

### 4. Populate your device inventory

Edit `sample_devices.xlsx` (the `Devices` sheet), or use a `.csv` or `.yaml` file with the same columns:

| Column | Required | Description |
|--------|----------|-------------|
| `device_name` | ✅ | Hostname or label |
| `ip_address` | ✅ | Device IP address |
| `siem_platform` | ✅ | `qradar` / `splunk` / `sentinel` / `elastic` / `fortisiem` / `wazuh` / `sumologic` / `seceon` / `generic_rest` |
| `client_name` | Optional | Client/tenant name |
| `api_endpoint` | Optional | SIEM API URL for this device's client (overrides `base_url`) |
| `auth_ref` | Optional | Client/tenant key: picks `tenants:` overrides in config and prefixed credentials (see [Multi-client setups](#multi-client-setups)) |
| `notes` | Optional | Free-text notes |
| `criticality` | Optional | `critical` / `high` / `medium` / `low` — picks the threshold and can drive routing |
| `threshold_hours` | Optional | Hours without logs before this device is stale (overrides everything else) |
| `snooze_until` | Optional | No alerts for this device until this date/time |
| `device_type` | Optional | e.g. `firewall`, `domain_controller`, `edr` — used for ATT&CK coverage |
| `expected_log_types` | Optional | e.g. `traffic;system` — log types the device should send |
| `min_events_per_hour` | Optional | Alert if volume falls below this |

### 5. Run against your SIEM

Set `siem.mock_mode: false` and your SIEM's `base_url` in `config.yaml`, then:

```bash
siem-pulse --dry-run                       # check the inventory
siem-pulse                                 # one run
siem-pulse --siem qradar --client "Acme"   # limit to one SIEM / client
siem-pulse --schedule                      # every scheduler.interval_minutes
siem-pulse --help                          # all commands
```

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

## Supported SIEMs

Use the name in the inventory's `siem_platform` column.

| `siem_platform` | Platform | How last-seen is found | Credentials |
|-----------------|----------|------------------------|-------------|
| `qradar` | IBM QRadar | Log source `last_event_time` (bulk) or AQL | `QRADAR_SEC_TOKEN` |
| `splunk` | Splunk Enterprise / Cloud | `tstats latest(_time) by host` via export search | `SPLUNK_TOKEN` |
| `sentinel` | Microsoft Sentinel | KQL `max(TimeGenerated)` over CEF / Syslog / Windows / Heartbeat | `SENTINEL_CLIENT_ID` / `_SECRET` |
| `elastic` | Elastic / OpenSearch | Composite aggregation, `max(@timestamp)` per host | `ELASTIC_API_KEY` |
| `fortisiem` | FortiSIEM | Event query on `phRecvTime` (per device or grouped) | `FORTISIEM_USER` / `_PASS` |
| `wazuh` | Wazuh | Agent `lastKeepAlive` | `WAZUH_USER` / `_PASS` |
| `sumologic` | Sumo Logic | Search job `max(_receipttime) by _sourcehost` | `SUMO_ACCESS_ID` / `_KEY` |
| `seceon` | Seceon aiSIEM | Configurable endpoint (per device or bulk) | `SECEON_API_KEY` |
| `generic_rest` | Anything with a REST list of sources | Configurable path, fields and paging | `GENERIC_REST_TOKEN` |

Example `generic_rest` recipe for **LogRhythm** (Admin API — check the field names against your version):

```yaml
siem:
  generic_rest:
    base_url: "https://logrhythm.example.com:8501"
    path: "/lr-admin-api/logsources"
    items_field: ""
    name_field: "host.name"
    ip_field: "host.name"
    time_field: "maxLogDate"
    pagination: offset
    offset_param: offset
    limit_param: count
```

**Plugins:** other packages can add connectors or alert channels without changing SIEM Pulse, through the entry-point groups `siem_pulse.connectors` and `siem_pulse.channels`:

```toml
[project.entry-points."siem_pulse.connectors"]
graylog = "siem_pulse_graylog:GraylogClient"     # a BaseSIEMClient subclass
```

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

## Alerts that only fire on change

Every run is stored in `siem_pulse.db` (SQLite, `state.path`). Alerts compare the new run with the last one:

| Group | Meaning | Sent |
|-------|---------|------|
| 🆕 New | Device just became stale/error (or a snooze ended and it is still down) | Immediately |
| 🔁 Reminder | Still down, already alerted | Every `repeat_after_hours` (default 24h) |
| ✅ Recovered | Logs flowing again | Once |

A device that stays down for a week produces one alert plus daily reminders, not 168 hourly alerts. An alert that could not be delivered anywhere is retried on the next run. Set `alerting.mode: every_run` for the old behaviour.

**Thresholds:** a device's `threshold_hours` column wins; otherwise its `criticality` picks `logic.criticality_thresholds` (default critical 1h, high 4h, medium 24h, low 72h); otherwise `logic.threshold_hours`.

**Snoozes and maintenance:**

```bash
siem-pulse --snooze "fw-01" --until 4h --reason "RMA"      # name or IP, * wildcards allowed
siem-pulse --snooze "acme-*" --until 2026-11-01T08:00
siem-pulse --list-snoozes
siem-pulse --unsnooze "fw-01"
```

Weekly or one-off `maintenance_windows` in `config.yaml` match devices by client, SIEM, criticality, name or type. Suppressed devices are still checked and shown with 🔕, but not alerted.

**Channels and routing:** define named `alerting.channels` and send each client or criticality to the right place with `alerting.routes` (examples in `config.yaml`):

| Type | What it does | Secrets |
|------|--------------|---------|
| `email` | HTML + plain-text summary | `SMTP_PASSWORD` |
| `slack` | Block Kit message, split to fit Slack limits | `SLACK_WEBHOOK_URL` |
| `teams` | Adaptive Card to a Teams workflow / incoming webhook | `TEAMS_WEBHOOK_URL` |
| `webhook` | JSON for SOAR (XSOAR, Splunk SOAR, Shuffle, n8n), optional HMAC signature | `url` / `hmac_secret` |
| `pagerduty` | One incident per device, auto-resolved on recovery | `PAGERDUTY_ROUTING_KEY` |
| `opsgenie` | One alert per device, closed on recovery | `OPSGENIE_API_KEY` |
| `servicenow` | One incident per outage, work notes on reminders, resolved on recovery | `SERVICENOW_USER` / `SERVICENOW_PASS` |
| `jira` | One issue per outage, comments, optional resolve transition | `JIRA_EMAIL` + `JIRA_API_TOKEN` |

Ticket ids are stored, so re-runs never create duplicates. **Daily digest:** set `alerting.digest` or run `siem-pulse --digest`.

## Deeper detection: alive but broken

A device can pass the last-seen check while its logs are useless: a firewall that only sends system messages after a config change, a parser that broke after an upgrade, a clock that drifted. Turn on `detection.enabled` and each run also measures, per source, over the last `window_hours`:

| Check | Finding when |
|-------|--------------|
| Volume drop | events/hour < `drop_ratio` × the `baseline_days` median (needs `min_samples` runs of history) |
| Volume floor | events/hour < the device's `min_events_per_hour` |
| Missing log types | an `expected_log_types` entry (e.g. `traffic`) matches none of the categories / sourcetypes / tables seen |
| Unparsed events | more than `unparsed_ratio` of events could not be parsed |
| Clock skew | event time and receive time differ by more than `max_clock_skew_minutes` |

Devices with findings become **🟠 degraded** and alert like stale devices (or set `findings_status: healthy` to only report them). Supported on QRadar, Splunk, Elastic, Sentinel and FortiSIEM (`lookup: grouped`).

## Coverage and ATT&CK blind spots

Every run prints a **coverage score** per client (healthy share of devices, weighted by criticality; degraded counts half) and, using the inventory's `device_type` column, the **MITRE ATT&CK data sources** that have no working log source:

```
  COVERAGE BY CLIENT (criticality-weighted)
    Acme Corp                      ███████░░░  72.7%  11 devices  (2 down)

  ATT&CK BLIND SPOTS (no working log source for these data sources)
    Acme Corp                      Network Traffic (DS0029) — down: fw-edge-01, fw-edge-02
```

Built-in device types: `firewall`, `ngfw`, `router`, `switch`, `ids`, `ips`, `waf`, `proxy`, `vpn`, `dns`, `domain_controller`, `windows_server`, `windows_workstation`, `linux_server`, `edr`, `email_gateway`, `identity_provider`, `cloud`, `database`, `web_server`. Add your own under `attack.device_types`. Data-source names and IDs follow ATT&CK v17.

## Dashboard, metrics and operations

```bash
siem-pulse --dashboard                      # http://127.0.0.1:8080 (reads the run history)
siem-pulse --schedule --dashboard           # checks + dashboard in one process
siem-pulse --check-heartbeat                # alert + exit 2 if no run finished recently
```

- **Dashboard:** overview cards, trend, coverage per client, open issues, ATT&CK blind spots and a page per client. No extra dependencies, no external assets, strict security headers.
- **Access control:** `dashboard.users` gives each user a token and a list of clients (`"*"` for all). Customers can see only their own devices, including in the API and metrics. Without users the dashboard only listens on localhost.
- **API:** `/api/summary`, `/api/issues`, `/api/runs` (JSON).
- **Prometheus:** `/metrics` (`siem_pulse_up`, `siem_pulse_devices{client,siem,status}`, `siem_pulse_client_coverage_score`, `siem_pulse_device_hours_since_last_log`, run time and duration), or write them to a node_exporter textfile with `metrics.textfile`. A Grafana dashboard is in `deploy/grafana/`.
- **Is the monitor itself alive?** `/healthz` returns 503 when no run finished within `heartbeat.max_age_minutes`; `heartbeat.ping_url` pings Healthchecks.io / Cronitor / Uptime Kuma after every run (and `/fail` on a crash); `--check-heartbeat` alerts your channels once.
- **Logs:** `logging.format: json` writes one JSON object per line for Splunk / Elastic / Loki.

## Deploy

| Option | Files |
|--------|-------|
| Docker | `docker build -t siem-pulse .` then `docker compose up -d` (set `DASHBOARD_TOKEN_ADMIN` in `.env`) |
| Kubernetes (Helm) | `helm install siem-pulse deploy/helm/siem-pulse` — checks + dashboard in one pod, history on a PVC |
| Kubernetes (plain) | `deploy/kubernetes/cronjob.yaml` — hourly CronJob |
| Linux server | `deploy/systemd/` — hourly timer, dashboard service, self-check timer |

Details and install commands: [deploy/README.md](deploy/README.md). The image runs as a non-root user and works with a read-only root filesystem. Behind a TLS-inspecting proxy, build with `--secret id=pip_ca,src=corp-ca.pem`.

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

## Secrets managers

By default credentials come from environment variables (or `.env`). To use a secrets manager, set `secrets.provider` in `config.yaml`:

| Provider | Where a secret lives | Extra install |
|----------|----------------------|---------------|
| `env` (default) | `ACME_QRADAR_SEC_TOKEN` (tenant prefix + name) | – |
| `vault` | HashiCorp Vault KV v2 at `<mount>/siem-pulse/<tenant>`, key `QRADAR_SEC_TOKEN`; token from `VAULT_TOKEN` | – |
| `aws` | AWS Secrets Manager JSON secret `siem-pulse/<tenant>`, key `QRADAR_SEC_TOKEN` | `boto3` |
| `azure` | Azure Key Vault secret `ACME-QRADAR-SEC-TOKEN` | `azure-identity azure-keyvault-secrets` |

Devices without an `auth_ref` use the tenant `default`. A tenant's lookup never falls back to `default`.

## Inventory from ServiceNow

Set `devices.source: servicenow` to read devices from a CMDB table instead of a file. Map ServiceNow fields to inventory columns with `field_map`, and fill gaps with `defaults`. Credentials: `SERVICENOW_USER` / `SERVICENOW_PASS`. See the commented example in `config.yaml`.

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

Write a connector class (subclass `InventoryClient` for bulk APIs or `BaseSIEMClient` for per-device APIs) and either register it in `siem_pulse/siem_clients/factory.py` or publish it as a plugin under the `siem_pulse.connectors` entry point. Step-by-step example: [docs/plugins.md](docs/plugins.md).

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
# Run every hour, and check every 15 minutes that runs are still happening
7 * * * *    cd /var/lib/siem-pulse && siem-pulse --config /etc/siem-pulse/config.yaml
*/15 * * * * cd /var/lib/siem-pulse && siem-pulse --config /etc/siem-pulse/config.yaml --check-heartbeat
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

Contributions are welcome — new SIEM connectors and alert channels especially. See [CONTRIBUTING.md](CONTRIBUTING.md), the [Code of Conduct](CODE_OF_CONDUCT.md) and the [Security Policy](SECURITY.md). Release history: [CHANGELOG.md](CHANGELOG.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify and distribute this software, including commercially, under the terms of that license. See [NOTICE](NOTICE).
