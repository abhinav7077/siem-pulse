# IBM QRadar

## Credentials

**Admin → Authorized Services → Add Authorized Service.** A security profile that can see the relevant log sources and the *Log Activity* permission is enough. Set the token as `QRADAR_SEC_TOKEN` (or `<AUTH_REF>_QRADAR_SEC_TOKEN` per client).

## Configuration

```yaml
siem:
  qradar:
    base_url: "https://qradar.example.com/api"
    verify_ssl: "/etc/ssl/qradar-ca.pem"   # or true / false
    api_version: "14.0"
    lookup: log_sources                    # log_sources (recommended) | aql
    max_concurrent_requests: 5
```

## Lookup modes

**`log_sources` (default)** reads every log source with its `last_event_time` from `GET /config/event_sources/log_source_management/log_sources` — one paged call per QRadar, cached for `inventory_cache_seconds`. A device matches when its IP equals the log source **identifier**, or its name equals the log source **name** or **identifier**. Tip: name devices in the inventory like their log sources, or use the IP identifier.

**`aql`** runs one Ariel search per device, polls it until `COMPLETED`, reads it and deletes it. The query comes from `aql_template` (`{ip}`, `{device_name}` placeholders); the default matches `LOGSOURCENAME(logsourceid)` to the device name. Slower; use it only when log source identifiers don't help.

## Deeper detection

With `detection.enabled`, one extra AQL search per run groups events by log source, high-level category and `isunparsed`, with `MAX/MIN(starttime - devicetime)` for clock skew. Override it with `metrics_aql` (columns: `logsourceid`, `log_type`, `events`, optional `isunparsed`, `max_lag`, `min_lag` in ms; `{minutes}` placeholder).

## Troubleshooting

- `HTTP 401/403` — token revoked, or the security profile cannot see the log sources.
- Device shows `Never / Not Found` — no log source identifier/name matches. Run `siem-pulse --reconcile --siem qradar` to see what QRadar knows.
