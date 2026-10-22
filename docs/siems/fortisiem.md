# FortiSIEM

## Credentials

A FortiSIEM user with API access. On service-provider (multi-tenant) deployments use the `organization/user` form, e.g. `super/admin`. Set `FORTISIEM_USER` / `FORTISIEM_PASS`.

## Configuration

```yaml
siem:
  fortisiem:
    base_url: "https://fortisiem.example.com/phoenix/rest"
    verify_ssl: true
    lookup: per_device             # per_device | grouped
    query_window_hours: 72
```

SIEM Pulse uses the event query API: submit an XML query → poll `/query/progress/{id}` → read `/query/events/{id}/…`.

- **`per_device`** filters on `reptDevIpAddr` and reads the newest `phRecvTime`.
- **`grouped`** runs one query per tenant grouped by reporting device with `MAX(phRecvTime)` — much faster for large inventories, and enables `--reconcile` and deeper detection (event counts per `eventType`; types starting with `Unknown` count as unparsed).
