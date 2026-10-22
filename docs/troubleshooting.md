# Troubleshooting

| Symptom | Check |
|---------|-------|
| `FileNotFoundError` for the inventory | Run from the folder with `config.yaml`, pass `--device-file`, or put the inventory next to the config |
| `Credential not set: X` | Add `X` to `.env` (or your secrets provider). With an `auth_ref`, the name is prefixed: `ACME_QRADAR_SEC_TOKEN` |
| `authentication/authorisation failed (HTTP 401)` | Wrong or expired token / password, or missing API permission — not retried |
| `TLS/SSL error` | Set `verify_ssl` to your internal CA bundle path |
| Device `Never / Not Found` | The SIEM has no source matching its IP or name — `siem-pulse --reconcile --siem <name>` shows what it knows |
| Everything stale right after enabling criticality | Critical/high thresholds are 1h/4h by default — tune `logic.criticality_thresholds` |
| No alerts arrive | `alerting` channels enabled? Check the run log for `channels ok/failed`. A device already alerted is only re-sent after `repeat_after_hours` |
| Dashboard refuses to start | It needs `dashboard.users` (or `allow_anonymous: true`) when not on localhost |
| `/healthz` returns 503 | No run finished within `heartbeat.max_age_minutes` — is the scheduler running? |
| Rate limited (HTTP 429) | Lower `max_concurrent_requests` / set `requests_per_second` for that SIEM |
