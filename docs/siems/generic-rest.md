# Generic REST connector

For any platform with a REST endpoint that lists sources and their last event time. Set `siem_platform: generic_rest`.

```yaml
siem:
  generic_rest:
    base_url: "https://siem.example.com"
    path: "/api/log-sources"
    method: GET                     # or POST with body
    items_field: "data.items"       # where the list is ("" when the response is the list)
    ip_field: "ip"
    name_field: "name"
    time_field: "lastEventTime"     # ISO 8601 or epoch seconds/ms; dots for nested fields
    auth: header                    # header (GENERIC_REST_TOKEN) | basic (GENERIC_REST_USER/PASS) | none
    auth_header: "Authorization"
    auth_scheme: "Bearer"
    pagination: offset              # none | offset | page
    page_size: 500
```

Use `tenants:` keyed by `auth_ref` to point different clients at different platforms, each with its own mapping.

## Recipe: LogRhythm (Admin API)

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
    limit_param: count
```

Check the field names against your LogRhythm version. Recipes for other platforms are welcome as pull requests.
