# Alerting

## Alerts that fire on change

Every run is stored in SQLite (`state.path`, default `siem_pulse.db`). Each run is compared with the previous state of every device:

| Group | Meaning | Sent |
|-------|---------|------|
| 🆕 New | Device just became stale, error or degraded (or a snooze ended and it is still down) | Immediately |
| 🔁 Reminder | Still down, already alerted | Every `repeat_after_hours` (default 24) |
| ✅ Recovered | Logs flowing again | Once |

An issue that could not be delivered anywhere stays "new" and is retried next run. `alerting.mode: every_run` restores the old "every issue, every run" behaviour.

```yaml
alerting:
  mode: changes
  repeat_after_hours: 24
  notify_recovered: true
```

## Thresholds

A device is **stale** when its last log is older than its threshold:

1. the device's `threshold_hours` column, else
2. `logic.criticality_thresholds[criticality]` (default critical 1h, high 4h, medium 24h, low 72h), else
3. `logic.threshold_hours` (default 24).

## Channels

The simple setup — `alerting.email` / `alerting.slack` with `enabled: true` — sends everything to those two. For more, define named channels:

```yaml
alerting:
  channels:
    soc_email:  {type: email, smtp_server: smtp.example.com, sender: soc@example.com, recipients: [soc@example.com]}
    soc_teams:  {type: teams, webhook_secret: TEAMS_WEBHOOK_URL}
    oncall:     {type: pagerduty, routing_key_secret: PAGERDUTY_ROUTING_KEY}
    opsgenie:   {type: opsgenie, api_key_secret: OPSGENIE_API_KEY, api_url: "https://api.eu.opsgenie.com"}
    tickets:    {type: servicenow, instance_url: "https://acme.service-now.com", assignment_group: SOC}
    jira:       {type: jira, base_url: "https://acme.atlassian.net", project_key: SOC, resolve_transition_id: "31"}
    soar:       {type: webhook, url: "https://soar.example/hooks/siem-pulse", hmac_secret: SOAR_HMAC_KEY}
```

| Type | Behaviour |
|------|-----------|
| `email` | HTML + plain-text summary (`password_secret`, default `SMTP_PASSWORD`; `auth: false` for open relays) |
| `slack` | Block Kit summary, split into several messages to fit Slack's limits |
| `teams` | Adaptive Card to a Teams workflow / incoming webhook |
| `webhook` | JSON body (`new`, `reminders`, `recovered`, `ongoing`), optional `X-SiemPulse-Signature: sha256=<hmac>` |
| `pagerduty` | Events API v2 — one incident per device (dedup key), resolved on recovery |
| `opsgenie` | One alert per device (alias), closed on recovery |
| `servicenow` | One incident per outage; work notes on reminders; resolved on recovery |
| `jira` | One issue per outage; comments; optional resolve transition (`JIRA_EMAIL` + `JIRA_API_TOKEN`, or `auth: bearer`) |

Ticket and incident ids are stored, so re-runs never create duplicates. A failing channel never blocks the others.

## Routing

```yaml
alerting:
  default_channels: [soc_email, soc_teams]   # anything that matches no route
  routes:                                     # first match wins unless continue: true
    - match: {criticality: critical}
      channels: [oncall]
      continue: true
    - match: {client_name: "Acme*"}           # globs, lists and case-insensitive matching
      channels: [acme_email, tickets]
```

Match keys: `client_name`, `siem_platform`, `criticality`, `device_name`, `device_type`, `auth_ref`, `ip_address`, `status`.

## Daily digest

```yaml
alerting:
  digest: {enabled: true, time: "08:00", timezone: "Europe/London", channels: [soc_email]}
```

Or send one now with `siem-pulse --digest`.

## Snoozes and maintenance windows

```bash
siem-pulse --snooze "fw-01" --until 4h --reason "RMA"    # name or IP; * wildcards
siem-pulse --list-snoozes
siem-pulse --unsnooze "fw-01"
```

```yaml
maintenance_windows:
  - name: "Acme patch night"
    match: {client_name: "Acme Corp"}
    weekly: {days: [sat], start: "22:00", end: "04:00", timezone: "Europe/London"}
  - name: "DC migration"
    match: {device_name: "dc-*"}
    start: "2026-11-02T18:00:00Z"
    end: "2026-11-03T06:00:00Z"
```

Suppressed devices are still checked and shown with 🔕, but not alerted. The inventory column `snooze_until` works too.
