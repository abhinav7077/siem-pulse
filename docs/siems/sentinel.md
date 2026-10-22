# Microsoft Sentinel

## Credentials

Register an app in **Microsoft Entra ID**, create a client secret, and give the app the **Log Analytics Reader** role on the Sentinel workspace. Set `SENTINEL_CLIENT_ID` and `SENTINEL_CLIENT_SECRET`.

## Configuration

```yaml
siem:
  sentinel:
    workspace_id: "00000000-0000-0000-0000-000000000000"   # Log Analytics workspace ID
    tenant_id: "11111111-1111-1111-1111-111111111111"
    lookback_hours: 72
```

The default KQL looks at `CommonSecurityLog`, `Syslog`, `SecurityEvent`, `WindowsEvent` and `Heartbeat`, returning `Name`, `Ip`, `LastSeen` per device. Replace it with `query` (keep those columns, or change `name_column` / `ip_column` / `time_column`) to include other tables.

## Deeper detection

`metrics_query` returns `Events`, `LogTypes` (table names) and `MaxLagSeconds` (ingestion delay) per device. Use table names in `expected_log_types`, e.g. `CommonSecurityLog`.

## Cost

Queries scan the lookback window of each table. Keep `lookback_hours` modest and limit the `union` to the tables you need.
