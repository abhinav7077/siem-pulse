# Elastic / OpenSearch

## Credentials

Create an API key with `read` and `view_index_metadata` on the log indices and set `ELASTIC_API_KEY` (the base64 `id:api_key` value). Or use `ELASTIC_USER` / `ELASTIC_PASS`.

## Configuration

```yaml
siem:
  elastic:
    base_url: "https://elastic.example.com:9200"
    index: "logs-*,filebeat-*,winlogbeat-*"
    host_field: host.name          # keyword field
    ip_field: host.ip              # "" to group by name only
    time_field: "@timestamp"
    lookback_hours: 72
```

A composite aggregation (paged with `after_key`) returns `max(@timestamp)` per host. Network devices often log under `observer.name` / `observer.ip` — set `host_field` / `ip_field` accordingly (use a tenant per data source if they differ).

## Deeper detection

Uses `doc_count`, the top values of `log_type_field` (default `event.dataset`) and `max(event.ingested) - max(@timestamp)` (`ingest_time_field`) for ingestion delay.
