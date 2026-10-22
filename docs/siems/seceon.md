# Seceon

Seceon documents its API per tenant, so the request is configurable:

```yaml
siem:
  seceon:
    base_url: "https://<tenant>.seceon.com/api/v2"
    last_log_path: "/devices/{ip}/lastlog"           # {ip} and {device_name} allowed
    timestamp_fields: ["last_event_time", "lastEventTime"]   # dots for nested fields
    auth_header: "Authorization"
    auth_scheme: "Bearer"
```

Credentials: `SECEON_API_KEY`. If your tenant has an endpoint that lists all devices with their last event time, use bulk mode (one call per tenant, enables `--reconcile`):

```yaml
    lookup: bulk
    bulk_path: "/devices"
    bulk_items_field: "items"
    bulk_ip_field: "ip"
    bulk_name_field: "name"
```

!!! note
    The defaults are a best guess. Check them against your tenant's API documentation; please open an issue with the correct paths so the defaults can be improved.
