# Splunk

## Credentials

Create an authentication token (**Settings → Tokens**) for a user whose role can search the relevant indexes, and set `SPLUNK_TOKEN`. Without a token, `SPLUNK_USER` / `SPLUNK_PASS` are used (basic auth).

## Configuration

```yaml
siem:
  splunk:
    base_url: "https://splunk.example.com:8089"      # management port; Splunk Cloud: https://<stack>.splunkcloud.com:8089
    lookback_hours: 72
    search: "| tstats latest(_time) as last_seen where index=* earliest=-{hours}h by host"
    host_field: host
    time_field: last_seen
```

One export search (`/services/search/jobs/export`) lists the newest event per `host`. The `host` value is matched against both the device IP and name. Narrow `index=*` to the indexes you care about to make it faster.

## Deeper detection

`metrics_search` (default `| tstats count max(_indextime) as indexed max(_time) as latest where index=* earliest=-{minutes}m by host sourcetype`) gives event counts and **sourcetypes** per host — use sourcetype fragments in `expected_log_types`, e.g. `traffic;threat` for `pan:traffic` / `pan:threat`. Clock skew is the gap between newest index time and newest event time.
