# Deeper detection & ATT&CK coverage

## Alive but broken

A device can pass the last-seen check while its logs are useless: a firewall that only sends system messages after a config change, a parser that broke after an upgrade, a drifting clock.

```yaml
detection:
  enabled: true
  window_hours: 1
  baseline_days: 7
  min_samples: 12
  drop_ratio: 0.2
  unparsed_ratio: 0.2
  max_clock_skew_minutes: 15
  findings_status: degraded     # degraded (alerts) | healthy (report only)
```

| Check | Finding when |
|-------|--------------|
| Volume drop | events/hour < `drop_ratio` × the median of the last `baseline_days` (after `min_samples` runs) |
| Volume floor | events/hour < the device's `min_events_per_hour` |
| Missing log types | an `expected_log_types` entry matches none of the categories / sourcetypes / tables seen |
| Unparsed events | more than `unparsed_ratio` of events could not be parsed |
| Clock skew | event time vs receive time differ by more than `max_clock_skew_minutes` |

Devices with findings become **🟠 degraded** and flow through the same alerts and tickets as stale devices. Supported on QRadar, Splunk, Elastic, Sentinel and FortiSIEM (`lookup: grouped`); each costs one extra query per tenant per run.

## Coverage score

Every run prints, per client, the criticality-weighted share of healthy devices (critical 4, high 3, medium 2, low 1; degraded counts half; suppressed devices are left out). It is also on the dashboard and in Prometheus as `siem_pulse_client_coverage_score`.

## MITRE ATT&CK blind spots

The inventory column `device_type` says what a device's logs are good for. Each type maps to ATT&CK data sources; a data source is **blind** for a client when every device that provides it is stale or erroring.

| `device_type` | Data sources |
|---------------|--------------|
| `firewall` | Network Traffic, Firewall |
| `domain_controller` | Logon Session, User Account, Active Directory, Process |
| `edr` | Process, Command, File, Windows Registry, Script |
| `proxy` | Network Traffic, Domain Name |
| `vpn` | Logon Session, Network Traffic, User Account |
| `dns` | Domain Name |

…and `ngfw`, `router`, `switch`, `ids`, `ips`, `waf`, `windows_server`, `windows_workstation`, `linux_server`, `email_gateway`, `identity_provider`, `cloud`, `database`, `web_server`. Add your own:

```yaml
attack:
  device_types:
    nac: ["Network Traffic", "Logon Session"]
```

Names and IDs (e.g. Network Traffic = DS0029) follow ATT&CK v17.
