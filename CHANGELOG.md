# Changelog

All notable changes to SIEM Pulse are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-22

First public release under the Apache License 2.0.

### Added
- **Connectors:** IBM QRadar (log sources API or AQL), FortiSIEM (per-device or grouped event queries), Seceon (configurable), Splunk, Microsoft Sentinel, Elastic / OpenSearch, Wazuh, Sumo Logic, a configurable generic REST connector, and connector plugins (`siem_pulse.connectors`).
- **Multi-client:** `api_endpoint` / `auth_ref` per device, per-tenant config overrides and credentials with no cross-tenant fallback, secrets providers (env, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault), ServiceNow CMDB inventory, CSV and YAML inventories.
- **Scale:** bulk lookups (one query per tenant), per-tenant rate and concurrency limits, pooled HTTP sessions, `--reconcile`.
- **Alerting:** SQLite run history; alerts on change (new, reminder, recovered); per-device thresholds and criticality; snoozes and maintenance windows; routing per client/criticality; daily digest; channels for email, Slack, Microsoft Teams, generic webhook (HMAC), PagerDuty, Opsgenie, ServiceNow and Jira with one ticket per outage; channel plugins (`siem_pulse.channels`).
- **Deeper detection:** volume baselines, volume floor, missing log types, unparsed events and clock skew; new `degraded` status; coverage score per client; MITRE ATT&CK data-source blind spots.
- **Operations:** built-in dashboard with per-client access, JSON API, Prometheus metrics and textfile export, `/healthz`, heartbeat pings, `--check-heartbeat`, JSON logs, Docker image, Compose, Helm chart, Kubernetes CronJob, systemd units, Grafana dashboard.
- **Project:** `siem_pulse` package with `siem-pulse` command and `--init`, `.env` loading, repeatable mock mode, tests and CI, docs site, release automation.

### Fixed
- QRadar searches are polled until complete; matching uses log sources instead of `sourceip`.
- FortiSIEM uses the real XML query flow and honours `verify_ssl`.
- Only temporary errors are retried; `Retry-After` is honoured.
- HTML/Slack escaping in alerts, correct email footer, `sheet_name` honoured, no `inf` in CSV reports.

## [0.1.0]

- Initial prototype: Excel inventory, QRadar / FortiSIEM / Seceon clients, email and Slack alerts, CSV report.

[Unreleased]: https://github.com/abhinav7077/siem-pulse/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/abhinav7077/siem-pulse/releases/tag/v0.2.0
