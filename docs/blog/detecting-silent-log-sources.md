# Detecting silent log sources: the SIEM blind spot nobody alerts on

*How SOC and MSSP teams can automatically find firewalls, servers and domain controllers that stopped sending logs — before an incident review does.*

Every SOC has a version of this story. An incident lands, the analyst pivots to the perimeter firewall's logs — and there are none for the last nine days. A change window reset the syslog target; nobody noticed, because **a log source that stops sending logs produces no alert at all**. Detection rules don't fire on data that never arrives.

## Why silent log sources happen

- **Configuration drift:** firmware upgrades, change windows or template pushes reset syslog/agent targets.
- **Collector problems:** a WinCollect/Universal Forwarder/agent dies, a disk fills, a certificate expires.
- **Network paths:** a new ACL or NAT rule drops UDP 514 or the collector's port.
- **Parsing:** logs still arrive but land as "unknown" events after a vendor format change — alive, but useless.
- **Onboarding gaps:** a new server never got added — or was added to the wrong client tenant.

## What "monitoring log sources" should mean

A useful log source health check answers four questions, per client:

1. **Is every expected device sending logs?** Compare each device's *last event time* with a threshold that fits its criticality — a domain controller silent for an hour matters more than a lab VM silent for a day.
2. **Is it sending the right logs?** Volume against a baseline, expected log types (traffic *and* system, not just system), parse failures and clock skew.
3. **What can't we see right now?** Map device types to MITRE ATT&CK data sources: if both firewalls are down, *Network Traffic* is blind.
4. **Do we know about every source?** Reconcile the SIEM's sources with the asset inventory in both directions.

And it has to alert like a grown-up tool: once when something breaks, a reminder if it stays broken, once when it recovers — routed to the team that owns it, ideally as a ticket that closes itself.

## Doing it with SIEM Pulse

[SIEM Pulse](https://github.com/abhinav7077/siem-pulse) is an open-source (Apache 2.0) Python tool that does exactly this across **IBM QRadar, Splunk, Microsoft Sentinel, Elastic, FortiSIEM, Wazuh, Sumo Logic and Seceon**, with one bulk query per SIEM tenant:

```bash
pip install siem-pulse
siem-pulse --init && siem-pulse          # mock mode first, no SIEM needed
```

- QRadar: log source `last_event_time` · Splunk: `tstats latest(_time) by host` · Sentinel: KQL `max(TimeGenerated)` · Elastic: `max(@timestamp)` per host.
- Alerts on change to email, Slack, Teams, PagerDuty, Opsgenie, ServiceNow or Jira; snoozes and maintenance windows.
- Volume baselines, missing log types, unparsed ratio and clock skew mark sources as *degraded*.
- A coverage score per client and an ATT&CK blind-spot report; a dashboard where each customer sees only their devices.

## A checklist you can use today, with or without a tool

- Keep an inventory of expected log sources **per client**, with criticality and device type.
- Set thresholds by criticality (e.g. 1h critical, 4h high, 24h medium, 72h low).
- Check last-seen **and** volume against a baseline — "alive" isn't "healthy".
- Reconcile SIEM sources with the inventory weekly.
- Alert on change, not every run; open one ticket per outage.
- Monitor the monitor: alert when the health check itself stops running.

*SIEM Pulse is open source — contributions, new connectors and feedback are welcome on [GitHub](https://github.com/abhinav7077/siem-pulse).*
