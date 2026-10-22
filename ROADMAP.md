# SIEM Pulse Roadmap

This roadmap takes SIEM Pulse from a working prototype to a production-grade,
multi-tenant **log source health monitor** for SOC and MSSP teams.

Each phase has a goal, a task list and an exit check. Phases are ordered by
impact: later phases build on earlier ones, so finish a phase's exit check
before starting the next one.

| Phase | Theme | Outcome |
|-------|-------|---------|
| [0](#phase-0) | Foundation & discoverability | Licensed, documented, findable, tested |
| [1](#phase-1) | Correctness against real SIEMs | Real API calls return correct results |
| [2](#phase-2) | Multi-tenant & scale | 100+ clients, 2,000+ devices in minutes |
| [3](#phase-3) | Alert quality | Alerts analysts trust, not noise |
| [4](#phase-4) | Deeper detection | Catch "alive but broken" log sources |
| [5](#phase-5) | Integrations | More SIEMs, alert channels and ticketing |
| [6](#phase-6) | Dashboard & operations | Easy to run, observe and deploy |
| [7](#phase-7) | Community & releases | Installable package, contributors, adoption |

Legend: `[x]` done · `[ ]` to do

---

<a id="phase-0"></a>

## Phase 0 — Foundation and discoverability

**Goal:** make the project legally reusable, easy to understand and easy to find
on GitHub and search engines.

- [x] Apache License 2.0 (`LICENSE`, `NOTICE`, SPDX headers in source files)
- [x] Search-friendly README: clear title, problem statement, keywords, badges
- [x] `pyproject.toml` with description, keywords, classifiers and project URLs
- [x] Public roadmap (this file) and `CONTRIBUTING.md`
- [ ] *(manual)* Add a GitHub repository description and topics (see the [Discoverability checklist](#discoverability))
- [x] Social preview image ready at `docs/assets/social-preview.png`
- [ ] *(manual)* Upload it: GitHub → Settings → Social preview
- [x] Unit tests with `pytest` (mocked HTTP per SIEM)
- [x] GitHub Actions CI: tests + mock-mode smoke run, Python 3.10–3.13 matrix
- [x] Add a linter (`ruff`) to CI
- [x] Load `.env` automatically with `python-dotenv`
- [x] Make mock mode deterministic (`mock_seed` in config) so demos and tests repeat

**Exit check:** CI is green on every push and the repo shows up when searching
GitHub for "SIEM log source monitoring".

---

<a id="phase-1"></a>

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

<a id="phase-2"></a>

## Phase 2 — Multi-tenant and scale

**Goal:** monitor 100+ client environments and 2,000+ devices accurately and fast.

- [x] Use the `api_endpoint` and `auth_ref` inventory columns
- [x] Cache SIEM clients per `(platform, endpoint, auth_ref)` instead of per platform
- [x] Credential lookup per tenant (`<AUTH_REF>_<VAR>` env vars, no fallback to default credentials)
- [x] Secrets manager backends: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- [x] **Bulk mode:** one "list all log sources + last seen" call per SIEM tenant, matched locally against the inventory (turns thousands of API calls into a handful)
- [x] **Inventory reconciliation:** report sources in the SIEM but not in Excel, and devices in Excel never seen by the SIEM
- [x] Per-SIEM rate limiting and concurrency limits
- [x] Inventory files besides Excel: CSV and YAML
- [x] Inventory from a CMDB / ServiceNow API
- [x] Reuse HTTP sessions (`requests.Session`) for connection pooling

**Exit check:** a 2,000-device, 100-client run finishes in under 5 minutes with
no cross-tenant credential use. *(Passes in a simulated test: 100 tenants make
100 bulk calls in total, and a tenant without its own credentials sends nothing.
Still needs confirming against real tenants.)*

---

<a id="phase-3"></a>

## Phase 3 — Alert quality

**Goal:** every alert is actionable; repeated or expected outages do not spam the team.

- [x] Store each run's results in SQLite
- [x] State-aware alerts: **newly stale**, **still stale**, **recovered**
- [x] Alert only on state changes, plus a configurable daily digest
- [x] Per-device `threshold_hours` column (overrides the global 24h)
- [x] Per-device `criticality` (critical / high / medium / low) with different thresholds and channels
- [x] Maintenance windows and snooze (`snooze_until` column or CLI command)
- [x] Split Slack messages to stay under the 3,000-character block limit
- [x] Per-client alert routing (each client's team gets only their devices)
- [x] Plain-text email part alongside HTML

**Exit check:** a device that stays down for a week produces one alert plus
digest mentions, not 168 hourly alerts. *(Covered by tests: new → quiet →
reminder → recovered.)*

---

<a id="phase-4"></a>

## Phase 4 — Deeper detection

**Goal:** catch log sources that are sending *something* but not the right thing.

- [x] Event volume baselines (EPS per source) with drop alerts, e.g. "below 20% of 7-day median"
- [x] Detect missing log *types* (e.g. firewall sends system logs but no traffic logs)
- [x] Detect parsing failures / unknown-event spikes where the SIEM exposes them
- [x] Clock-skew detection (event time far from receive time)
- [x] Coverage scoring per client (percentage of expected sources healthy)
- [x] MITRE ATT&CK data source mapping: show which detections are blind when a source is down

**Exit check:** a simulated 90% volume drop on a healthy-looking source raises
an alert within one run. *(Covered by tests; real-SIEM metric queries still
need a live check — see the testing notes in the pull request.)*

---

<a id="phase-5"></a>

## Phase 5 — Integrations

**Goal:** work with the tools SOC teams already use.

### SIEM connectors
- [x] Splunk (REST export search with `tstats`)
- [x] Microsoft Sentinel (Log Analytics query API, KQL over common tables)
- [x] Elastic / OpenSearch (composite aggregation, max `@timestamp` per host)
- [x] Wazuh (agents API `lastKeepAlive`)
- [x] Sumo Logic (search job API)
- [x] Generic REST connector (configurable path, fields, auth, paging) with a LogRhythm recipe
- [ ] Dedicated Google SecOps (Chronicle), LogRhythm and ArcSight connectors (use `generic_rest` until then)
- [x] Plugin entry points so third-party connectors and channels install with `pip`

### Alert channels and ticketing
- [x] Microsoft Teams webhook
- [x] PagerDuty and Opsgenie
- [x] ServiceNow and Jira ticket creation with de-duplication (one ticket per outage)
- [x] Generic webhook (JSON) for SOAR platforms (Cortex XSOAR, Splunk SOAR, Shuffle)

**Exit check:** at least six SIEMs and four alert channels supported, each with tests.

---

<a id="phase-6"></a>

## Phase 6 — Dashboard and operations

**Goal:** make SIEM Pulse easy to deploy, run and watch.

- [x] Web dashboard (built in, no extra dependencies): health by client, trends, open issues, ATT&CK gaps
- [x] Prometheus `/metrics` endpoint and a sample Grafana dashboard
- [x] Dockerfile and `docker-compose.yml`
- [x] Helm chart / Kubernetes CronJob example
- [x] systemd unit and timer example
- [x] Structured JSON logging option
- [x] Health check of the monitor itself (alert if a scheduled run does not happen)
- [x] Role-based access for the dashboard when exposed to clients

**Exit check:** `docker compose up` gives a working dashboard on mock data in under a minute.
*(Verified: image built and run locally — first check and dashboard up in about 5 seconds.)*

---

<a id="phase-7"></a>

## Phase 7 — Community and releases

**Goal:** make SIEM Pulse easy to adopt and contribute to.

- [x] PyPI-ready package with a `siem-pulse` CLI command and `--init`
- [x] Release workflow: tests, PyPI (trusted publishing), GitHub release, multi-arch image on GHCR
- [ ] *(manual)* First release: add the PyPI trusted publisher, then push tag `v0.2.0`
- [x] Semantic versioning, `CHANGELOG.md`, GitHub Releases (automated from the changelog)
- [x] Documentation site (MkDocs Material) with setup guides per SIEM, built in CI
- [ ] *(manual)* Enable GitHub Pages: Settings → Pages → Source: GitHub Actions
- [x] `SECURITY.md` with a private vulnerability reporting process
- [x] Issue forms (bug, feature, new connector) and a pull request template; Dependabot
- [ ] *(manual)* Create labels `good first issue`, `connector`, `help wanted` and open starter issues
- [x] Code of conduct (Contributor Covenant 2.1) and `CITATION.cff`
- [ ] *(manual)* Submit to curated lists (e.g. awesome-security, awesome-siem, awesome-soc) after the first release
- [x] Blog post "Detecting silent log sources" on the docs site
- [ ] *(manual)* Share it: LinkedIn, r/blueteamsec, r/cybersecurity, SOC communities

**Exit check:** first external contribution merged and package downloadable from PyPI.
*(Everything is automated; the remaining steps need the repository owner's accounts.)*

---

<a id="discoverability"></a>

## Discoverability checklist

Things that help people find SIEM Pulse on GitHub and Google. Items marked
*(manual)* are repository settings that the owner sets on GitHub.

- [x] README starts with a keyword-rich title and one-paragraph problem statement
- [x] README mentions the exact terms people search for: *log source monitoring*, *log ingestion*, *silent log sources*, *SIEM health check*, *QRadar*, *FortiSIEM*, *Seceon*, *SOC automation*, *MSSP*
- [x] `pyproject.toml` keywords and classifiers (used by PyPI search)
- [x] Recognised open-source license (GitHub shows "Apache-2.0" in the sidebar)
- [ ] *(manual)* Repository description:
  `Open-source SIEM log source health monitor — find devices that stopped sending logs to QRadar, Splunk, Sentinel, Elastic, FortiSIEM, Wazuh and more. Multi-client SOC/MSSP automation in Python.`
- [ ] *(manual)* Website field: `https://abhinav7077.github.io/siem-pulse/`
- [ ] *(manual)* Repository topics:
  `siem`, `soc`, `log-monitoring`, `log-management`, `security-monitoring`, `qradar`, `splunk`, `microsoft-sentinel`, `elastic`, `fortisiem`, `wazuh`, `mssp`, `blue-team`, `cybersecurity`, `security-automation`, `mitre-attack`, `python`, `threat-detection`, `log-source-health`, `seceon`
- [ ] *(manual)* Upload the social preview image `docs/assets/social-preview.png` (1280×640)
- [ ] Publish a GitHub Release — automated by pushing tag `v0.2.0`
- [x] PyPI package metadata and docs site with keyword-rich pages and a blog post (go live with the first release / Pages)
- [ ] Share in communities: r/blueteamsec, r/cybersecurity, LinkedIn, SOC Discord/Slack groups
