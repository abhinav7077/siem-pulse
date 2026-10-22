# SIEM Pulse Roadmap

This roadmap takes SIEM Pulse from a working prototype to a production-grade,
multi-tenant **log source health monitor** for SOC and MSSP teams.

Each phase has a goal, a task list and an exit check. Phases are ordered by
impact: later phases build on earlier ones, so finish a phase's exit check
before starting the next one.

| Phase | Theme | Outcome |
|-------|-------|---------|
| [0](#phase-0--foundation-and-discoverability) | Foundation & discoverability | Licensed, documented, findable, tested |
| [1](#phase-1--correctness-against-real-siems) | Correctness against real SIEMs | Real API calls return correct results |
| [2](#phase-2--multi-tenant-and-scale) | Multi-tenant & scale | 100+ clients, 2,000+ devices in minutes |
| [3](#phase-3--alert-quality) | Alert quality | Alerts analysts trust, not noise |
| [4](#phase-4--deeper-detection) | Deeper detection | Catch "alive but broken" log sources |
| [5](#phase-5--integrations) | Integrations | More SIEMs, alert channels and ticketing |
| [6](#phase-6--dashboard-and-operations) | Dashboard & operations | Easy to run, observe and deploy |
| [7](#phase-7--community-and-releases) | Community & releases | Installable package, contributors, adoption |

Legend: `[x]` done · `[ ]` to do

---

## Phase 0 — Foundation and discoverability

**Goal:** make the project legally reusable, easy to understand and easy to find
on GitHub and search engines.

- [x] Apache License 2.0 (`LICENSE`, `NOTICE`, SPDX headers in source files)
- [x] Search-friendly README: clear title, problem statement, keywords, badges
- [x] `pyproject.toml` with description, keywords, classifiers and project URLs
- [x] Public roadmap (this file) and `CONTRIBUTING.md`
- [ ] Add a GitHub repository description and topics (see [Discoverability checklist](#discoverability-checklist))
- [ ] Add a social preview image (GitHub → Settings → Social preview)
- [x] Unit tests with `pytest` (mocked HTTP per SIEM)
- [x] GitHub Actions CI: tests + mock-mode smoke run, Python 3.10–3.13 matrix
- [x] Add a linter (`ruff`) to CI
- [x] Load `.env` automatically with `python-dotenv`
- [x] Make mock mode deterministic (`mock_seed` in config) so demos and tests repeat

**Exit check:** CI is green on every push and the repo shows up when searching
GitHub for "SIEM log source monitoring".

---

## Phase 1 — Correctness against real SIEMs

**Goal:** when `mock_mode: false`, every connector returns the correct last-seen
time for every device.

### IBM QRadar
- [x] Poll `GET /ariel/searches/{id}` until `COMPLETED` before reading results (currently reads immediately)
- [x] Use `GET /config/event_sources/log_source_management/log_sources` and its `last_event_time` field instead of an AQL query per device
- [x] If AQL is kept, match on log source (`logsourceid` / `LOGSOURCENAME`), not `sourceip`
- [x] Validate IP addresses before building any query (prevents AQL injection)

### FortiSIEM
- [x] Implement the real XML query flow: submit query → poll progress → fetch events
- [x] Honour a `verify_ssl` setting (true / false / CA bundle path) for every SIEM instead of hardcoded `verify=False`
- [x] Bulk lookup via a grouped query (`lookup: grouped`)

### Seceon OTM
- [x] Make the endpoint path, timestamp fields and auth header configurable (Seceon's API is documented per tenant)
- [ ] Confirm the default path/fields against a real Seceon tenant and update the defaults
- [x] Add response-schema validation with clear error messages

### Core fixes
- [x] Do not retry on 401/403 or other non-retryable errors; retry only timeouts, 429 and 5xx
- [x] Respect `Retry-After` on HTTP 429
- [x] Pass `devices.sheet_name` from config to `ExcelReader`
- [x] Write an empty value instead of `inf` for "never seen" in the CSV
- [x] Replace deprecated `datetime.utcnow()` with timezone-aware UTC
- [x] HTML-escape device names and error text in alert emails
- [x] Fix the email footer hint that prints `--client "ALL devices"`
- [x] Keep a single source of truth for supported SIEMs (registry, not two lists)

**Exit check:** each connector passes recorded-response tests *(done)* and a
manual run against one real tenant per SIEM *(needs access to real tenants)*.

---

## Phase 2 — Multi-tenant and scale

**Goal:** monitor 100+ client environments and 2,000+ devices accurately and fast.

- [x] Use the `api_endpoint` and `auth_ref` inventory columns
- [x] Cache SIEM clients per `(platform, endpoint, auth_ref)` instead of per platform
- [x] Credential lookup per tenant (`<AUTH_REF>_<VAR>` env vars, no fallback to default credentials)
- [ ] Secrets manager backends: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- [x] **Bulk mode:** one "list all log sources + last seen" call per SIEM tenant, matched locally against the inventory (turns thousands of API calls into a handful)
- [x] **Inventory reconciliation:** report sources in the SIEM but not in Excel, and devices in Excel never seen by the SIEM
- [x] Per-SIEM rate limiting and concurrency limits
- [x] Inventory files besides Excel: CSV and YAML
- [ ] Inventory from a CMDB / ServiceNow API
- [x] Reuse HTTP sessions (`requests.Session`) for connection pooling

**Exit check:** a 2,000-device, 100-client run finishes in under 5 minutes with
no cross-tenant credential use. *(Passes in a simulated test: 100 tenants make
100 bulk calls in total, and a tenant without its own credentials sends nothing.
Still needs confirming against real tenants.)*

---

## Phase 3 — Alert quality

**Goal:** every alert is actionable; repeated or expected outages do not spam the team.

- [ ] Store each run's results in SQLite (PostgreSQL optional)
- [ ] State-aware alerts: **newly stale**, **still stale**, **recovered**
- [ ] Alert only on state changes, plus a configurable daily digest
- [ ] Per-device `threshold_hours` column (overrides the global 24h)
- [ ] Per-device `criticality` (critical / high / medium / low) with different thresholds and channels
- [ ] Maintenance windows and snooze (`snooze_until` column or CLI command)
- [ ] Split Slack messages to stay under the 3,000-character block limit
- [ ] Per-client alert routing (each client's team gets only their devices)
- [ ] Plain-text email part alongside HTML

**Exit check:** a device that stays down for a week produces one alert plus
digest mentions, not 168 hourly alerts.

---

## Phase 4 — Deeper detection

**Goal:** catch log sources that are sending *something* but not the right thing.

- [ ] Event volume baselines (EPS per source) with drop alerts, e.g. "below 20% of 7-day median"
- [ ] Detect missing log *types* (e.g. firewall sends system logs but no traffic logs)
- [ ] Detect parsing failures / unknown-event spikes where the SIEM exposes them
- [ ] Clock-skew detection (event time far from receive time)
- [ ] Coverage scoring per client (percentage of expected sources healthy)
- [ ] MITRE ATT&CK data source mapping: show which detections are blind when a source is down

**Exit check:** a simulated 90% volume drop on a healthy-looking source raises
an alert within one run.

---

## Phase 5 — Integrations

**Goal:** work with the tools SOC teams already use.

### SIEM connectors
- [ ] Splunk (REST search / `metadata` command)
- [ ] Microsoft Sentinel (Log Analytics `Heartbeat` / `_IsBillable` queries)
- [ ] Elastic Security (`_search` max `@timestamp` per host)
- [ ] Wazuh (agents API `lastKeepAlive`)
- [ ] Google SecOps (Chronicle), LogRhythm, ArcSight, Sumo Logic
- [ ] Plugin entry points so third-party connectors install with `pip`

### Alert channels and ticketing
- [ ] Microsoft Teams webhook
- [ ] PagerDuty and Opsgenie
- [ ] ServiceNow and Jira ticket creation with de-duplication (one ticket per outage)
- [ ] Generic webhook (JSON) for SOAR platforms (Cortex XSOAR, Splunk SOAR, Shuffle)

**Exit check:** at least six SIEMs and four alert channels supported, each with tests.

---

## Phase 6 — Dashboard and operations

**Goal:** make SIEM Pulse easy to deploy, run and watch.

- [ ] Web dashboard (Streamlit or FastAPI + HTMX): health by client, by SIEM, trends over time
- [ ] Prometheus `/metrics` endpoint and a sample Grafana dashboard
- [ ] Dockerfile and `docker-compose.yml`
- [ ] Helm chart / Kubernetes CronJob example
- [ ] systemd unit and timer example
- [ ] Structured JSON logging option
- [ ] Health check of the monitor itself (alert if a scheduled run does not happen)
- [ ] Role-based access for the dashboard when exposed to clients

**Exit check:** `docker compose up` gives a working dashboard on mock data in under a minute.

---

## Phase 7 — Community and releases

**Goal:** make SIEM Pulse easy to adopt and contribute to.

- [ ] Publish to PyPI (`pip install siem-pulse`) with a `siem-pulse` CLI command
- [ ] Semantic versioning, `CHANGELOG.md`, GitHub Releases
- [ ] Documentation site on GitHub Pages (MkDocs Material): setup guides per SIEM
- [ ] `SECURITY.md` with a vulnerability reporting process
- [ ] Issue and pull request templates; "good first issue" labels (new connectors are ideal)
- [ ] Code of conduct
- [ ] Submit to curated lists (e.g. awesome-security, awesome-siem, awesome-soc)
- [ ] Write-ups: blog post / LinkedIn article on "detecting silent log sources"

**Exit check:** first external contribution merged and package downloadable from PyPI.

---

## Discoverability checklist

Things that help people find SIEM Pulse on GitHub and Google. Items marked
*(manual)* are repository settings that the owner sets on GitHub.

- [x] README starts with a keyword-rich title and one-paragraph problem statement
- [x] README mentions the exact terms people search for: *log source monitoring*, *log ingestion*, *silent log sources*, *SIEM health check*, *QRadar*, *FortiSIEM*, *Seceon*, *SOC automation*, *MSSP*
- [x] `pyproject.toml` keywords and classifiers (used by PyPI search)
- [x] Recognised open-source license (GitHub shows "Apache-2.0" in the sidebar)
- [ ] *(manual)* Repository description:
  `Open-source SIEM log source health monitor — detect devices that stopped sending logs to IBM QRadar, FortiSIEM and Seceon. Multi-client SOC/MSSP automation in Python.`
- [ ] *(manual)* Website field: link to the docs site once Phase 7 adds it
- [ ] *(manual)* Repository topics:
  `siem`, `soc`, `log-monitoring`, `log-management`, `security-monitoring`, `qradar`, `fortisiem`, `seceon`, `mssp`, `blue-team`, `cybersecurity`, `security-automation`, `log-source-health`, `python`, `threat-detection`
- [ ] *(manual)* Social preview image (1280×640) with name and tagline
- [ ] Publish a GitHub Release (releases are indexed and show in the sidebar)
- [ ] PyPI package and docs site (each is another indexed page linking back)
- [ ] Share in communities: r/blueteamsec, r/cybersecurity, LinkedIn, SOC Discord/Slack groups
