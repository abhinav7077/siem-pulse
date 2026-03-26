# SOC Log Health Monitor 🔍

A Python automation tool for SOC analysts to monitor log ingestion from multiple SIEM platforms — **Seceon OTM**, **IBM QRadar**, and **FortiSIEM** — across multiple client environments.

The tool checks whether devices listed in your device inventory are sending logs within the last 24 hours and alerts you when they're not.

---

## Features

- 📋 Reads device inventory from Excel (`.xlsx`)
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
soc_log_health_monitor/
├── main.py                        # Entry point
├── config.yaml                    # Configuration (no secrets)
├── .env.example                   # Environment variable template
├── requirements.txt               # Python dependencies
├── sample_devices.xlsx            # Example device inventory
├── reports/                       # CSV reports saved here (auto-created)
├── soc_monitor.log                # Log file (auto-created)
└── modules/
    ├── excel_reader.py            # Reads and validates device inventory
    ├── log_checker.py             # Checks last log time per device
    ├── report_generator.py        # Generates console + CSV reports
    ├── alerting.py                # Email + Slack alerts
    └── siem_clients/
        ├── base_client.py         # Abstract base for all SIEM clients
        ├── factory.py             # Instantiates the right client per device
        ├── seceon_client.py       # Seceon OTM API client
        ├── qradar_client.py       # IBM QRadar API client
        └── fortisiem_client.py    # FortiSIEM API client
```

---

## Quick Start

### 1. Clone / download the project

```bash
cd soc_log_health_monitor
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

Load the `.env` file before running:
```bash
# Linux/Mac
export $(cat .env | xargs)

# Or install python-dotenv and it loads automatically
```

### 4. Populate your device inventory

Edit `sample_devices.xlsx` — the `Devices` sheet must contain:

| Column | Required | Description |
|--------|----------|-------------|
| `device_name` | ✅ | Hostname or label |
| `ip_address` | ✅ | Device IP address |
| `siem_platform` | ✅ | `seceon` / `qradar` / `fortisiem` |
| `client_name` | Optional | Client/tenant name |
| `api_endpoint` | Optional | Override API endpoint |
| `auth_ref` | Optional | Reference to alternate credential |
| `notes` | Optional | Free-text notes |

### 5. Run the monitor

```bash
# Single run (mock mode — no real API calls)
python main.py

# Single run with real APIs (set mock_mode: false in config.yaml)
python main.py

# Run on a schedule (every 60 minutes by default)
python main.py --schedule

# Use a custom device file
python main.py --device-file /path/to/my_devices.xlsx

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

### Seceon OTM
1. Log into your Seceon tenant
2. Go to **Settings → API Keys → Generate**
3. Set `SECEON_API_KEY` in `.env`
4. Update `siem.seceon.base_url` in `config.yaml` to your tenant URL
5. Review `modules/siem_clients/seceon_client.py` — update the endpoint path and response parsing to match your Seceon version's API schema

### IBM QRadar
1. Go to **Admin → Authorized Services → Add Authorized Service**
2. Copy the **SEC token**
3. Set `QRADAR_SEC_TOKEN` in `.env`
4. Update `siem.qradar.base_url` in `config.yaml`
5. The client submits an AQL query — adjust the query in `qradar_client.py` if your event schema differs

### FortiSIEM
1. Ensure your FortiSIEM account has API/REST access
2. Set `FORTISIEM_USER` and `FORTISIEM_PASS` in `.env`
3. Update `siem.fortisiem.base_url` in `config.yaml`
4. Review the query payload in `fortisiem_client.py` — FortiSIEM uses an XML-based query API in older versions; adapt as needed

---

## Adding a New SIEM Platform

1. Create `modules/siem_clients/my_siem_client.py` inheriting `BaseSIEMClient`
2. Implement `get_last_log_time(device) -> Optional[datetime]`
3. Register it in `modules/siem_clients/factory.py`:
   ```python
   from .my_siem_client import MySIEMClient
   SIEM_REGISTRY["mysiem"] = MySIEMClient
   ```
4. Add config section under `siem:` in `config.yaml`
5. Add devices with `siem_platform: mysiem` to your Excel file

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

## Future Enhancements (Roadmap)

- [ ] **Streamlit dashboard** — Live web UI showing device health status
- [ ] **SQLite/PostgreSQL storage** — Historical trend tracking
- [ ] **Multi-threading** — Parallel SIEM queries for large device inventories
- [ ] **PagerDuty / Teams integration** — Additional alert channels
- [ ] **Auto-remediation hooks** — Trigger tickets in ServiceNow/Jira
- [ ] **Per-device custom thresholds** — Some devices may have longer expected gaps

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `FileNotFoundError: sample_devices.xlsx` | Run from project root directory |
| `SECEON_API_KEY not set` | Load your `.env` file before running |
| All devices show ERROR | Ensure `mock_mode: true` in config or verify SIEM connectivity |
| Email not sending | Check `SMTP_PASSWORD`, SMTP server, and port 587 access |
| `Unknown SIEM platform` | Ensure `siem_platform` column in Excel uses lowercase: `seceon`, `qradar`, `fortisiem` |
