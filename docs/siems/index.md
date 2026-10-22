# Supported SIEMs

| `siem_platform` | Platform | How last-seen is found | Bulk | Metrics ([detection](../detection.md)) |
|-----------------|----------|------------------------|:----:|:------:|
| `qradar` | [IBM QRadar](qradar.md) | Log source `last_event_time` (or AQL) | ✅ | ✅ |
| `splunk` | [Splunk](splunk.md) | `tstats latest(_time) by host` | ✅ | ✅ |
| `sentinel` | [Microsoft Sentinel](sentinel.md) | KQL `max(TimeGenerated)` | ✅ | ✅ |
| `elastic` | [Elastic / OpenSearch](elastic.md) | Composite aggregation `max(@timestamp)` | ✅ | ✅ |
| `fortisiem` | [FortiSIEM](fortisiem.md) | Event query on `phRecvTime` | grouped mode | grouped mode |
| `wazuh` | [Wazuh](wazuh.md) | Agent `lastKeepAlive` | ✅ | – |
| `sumologic` | [Sumo Logic](sumologic.md) | Search job `max(_receipttime)` | ✅ | – |
| `seceon` | [Seceon](seceon.md) | Configurable endpoint | bulk mode | – |
| `generic_rest` | [Anything else](generic-rest.md) | Configurable path and fields | ✅ | – |

**Bulk** connectors make one query per SIEM tenant and match devices locally, so 2,000 devices cost a handful of API calls. They also power `--reconcile`.

**Matching:** a device matches a SIEM source when its `ip_address` equals the source identifier/IP, or its `device_name` equals the source name or identifier (case-insensitive).

**Common settings** (every SIEM section and every tenant): `verify_ssl` (`true`, `false` or a CA bundle path), `max_concurrent_requests`, `requests_per_second`, `inventory_cache_seconds`, `lookback_hours` (bulk connectors).

Missing a platform? Use [generic REST](generic-rest.md) or write a [plugin](../plugins.md).
