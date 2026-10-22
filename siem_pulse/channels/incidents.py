# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
Per-device channels — one incident or ticket per device outage, opened when a
device goes quiet and closed when it recovers. Re-sends never create duplicates.

    pagerduty   Events API v2 (dedup_key per device)
                  {type: pagerduty, routing_key_secret: PAGERDUTY_ROUTING_KEY}
    opsgenie    Alert API (alias per device)
                  {type: opsgenie, api_key_secret: OPSGENIE_API_KEY,
                   api_url: "https://api.opsgenie.com"   # EU: https://api.eu.opsgenie.com
                   responders: [{type: team, name: SOC}]}
    servicenow  Incident per device; work note on reminders; resolved on recovery
                  {type: servicenow, instance_url, table: incident,
                   user_secret: SERVICENOW_USER, password_secret: SERVICENOW_PASS,
                   assignment_group: "SOC", caller_id: "siem.pulse",
                   resolve_state: "6", close_code: "Solved (Permanently)",
                   fields: {category: "Security"}}
    jira        Issue per device; comment on reminders; optional transition on recovery
                  {type: jira, base_url, project_key: SOC, issue_type: Task,
                   auth: basic  (JIRA_EMAIL + JIRA_API_TOKEN)  | bearer (JIRA_API_TOKEN),
                   resolve_transition_id: "31", labels: [siem-pulse]}

Ticket ids are kept in the state store, so a ticket is created once per outage.
"""

import re
from typing import Any, Dict, List, Optional

from ..alert_policy import AlertBatch
from .base import Channel, ChannelError, detail, device_label, incident_key

SEVERITY = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
OPSGENIE_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
SNOW_URGENCY = {"critical": "1", "high": "2", "medium": "3", "low": "3"}
SNOW_IMPACT = {"critical": "1", "high": "2", "medium": "2", "low": "3"}


def _summary(item: Dict[str, Any]) -> str:
    what = "no logs" if item.get("status") == "stale" else "log check failing"
    return f"[SIEM Pulse] {item.get('device_name')} ({item.get('client_name') or 'N/A'}) — {what}"


def _description(item: Dict[str, Any], group: str) -> str:
    return (
        f"Device: {device_label(item)}\n"
        f"Client: {item.get('client_name') or 'N/A'}\n"
        f"Status: {item.get('status')} — {detail(item, group)}\n"
        f"Unhealthy since: {item.get('since') or 'unknown'}\n"
        f"Notes: {item.get('notes') or '-'}\n\n"
        "Check the log source: device logging configuration, collector/agent, network path to the SIEM."
    )


class _PerDeviceChannel(Channel):
    per_device = True

    def send(self, batch: AlertBatch) -> List[str]:
        if batch.kind == "digest":
            return []
        notified, failures = [], []
        for group, items in (("new", batch.new), ("reminders", batch.reminders), ("recovered", batch.recovered)):
            for item in items:
                try:
                    if group == "recovered":
                        self.close(item)
                    else:
                        self.open(item, group)
                        notified.append(item["device_key"])
                except ChannelError as e:
                    failures.append(str(e))
                    self.logger.error(str(e))
        if failures and not notified and not batch.recovered:
            raise ChannelError(f"{self.id}: all {len(failures)} deliveries failed")
        return notified

    # Ticket bookkeeping in the state store
    def _ticket(self, item) -> Optional[str]:
        return self.store.get_ticket(item["device_key"], self.id) if self.store else None

    def _remember(self, item, reference: Optional[str]):
        if self.store:
            self.store.set_ticket(item["device_key"], self.id, reference)

    def open(self, item: Dict[str, Any], group: str):
        raise NotImplementedError

    def close(self, item: Dict[str, Any]):
        raise NotImplementedError


class PagerDutyChannel(_PerDeviceChannel):
    type_name = "pagerduty"
    URL = "https://events.pagerduty.com/v2/enqueue"

    def _event(self, item, action):
        key = self.secret("routing_key_secret", "PAGERDUTY_ROUTING_KEY")
        if not key:
            raise ChannelError(f"{self.id}: {self.cfg.get('routing_key_secret', 'PAGERDUTY_ROUTING_KEY')} is not set")
        event = {"routing_key": key, "event_action": action, "dedup_key": incident_key(item)}
        if action == "trigger":
            event["payload"] = {
                "summary": _summary(item)[:1024],
                "source": str(item.get("ip_address") or item.get("device_name")),
                "severity": SEVERITY.get(item.get("criticality") or "medium", "warning"),
                "component": item.get("device_name"),
                "group": item.get("client_name"),
                "class": "log-source-health",
                "custom_details": {"details": detail(item, "new"), "siem": item.get("siem_platform"),
                                   "since": item.get("since")},
            }
        self.http("POST", self.cfg.get("url", self.URL), json=event)

    def open(self, item, group):
        self._event(item, "trigger")

    def close(self, item):
        self._event(item, "resolve")


class OpsgenieChannel(_PerDeviceChannel):
    type_name = "opsgenie"

    def _headers(self):
        key = self.secret("api_key_secret", "OPSGENIE_API_KEY")
        if not key:
            raise ChannelError(f"{self.id}: {self.cfg.get('api_key_secret', 'OPSGENIE_API_KEY')} is not set")
        return {"Authorization": f"GenieKey {key}"}

    @property
    def base(self):
        return self.cfg.get("api_url", "https://api.opsgenie.com").rstrip("/")

    def open(self, item, group):
        body = {
            "message": _summary(item)[:130],
            "alias": incident_key(item),
            "description": _description(item, group)[:15000],
            "priority": OPSGENIE_PRIORITY.get(item.get("criticality") or "medium", "P3"),
            "tags": ["siem-pulse", str(item.get("siem_platform") or "")],
            "entity": str(item.get("device_name")),
            "source": "siem-pulse",
            "details": {"client": str(item.get("client_name")), "ip": str(item.get("ip_address"))},
        }
        if self.cfg.get("responders"):
            body["responders"] = self.cfg["responders"]
        self.http("POST", f"{self.base}/v2/alerts", json=body, headers=self._headers())

    def close(self, item):
        self.http("POST", f"{self.base}/v2/alerts/{incident_key(item)}/close",
                  params={"identifierType": "alias"},
                  json={"source": "siem-pulse", "note": "Logs are flowing again."},
                  headers=self._headers())


class ServiceNowChannel(_PerDeviceChannel):
    type_name = "servicenow"

    def _auth(self):
        user = self.secret("user_secret", "SERVICENOW_USER")
        password = self.secret("password_secret", "SERVICENOW_PASS")
        if not user or not password:
            raise ChannelError(f"{self.id}: ServiceNow credentials are not set")
        return (user, password)

    @property
    def table_url(self):
        base = str(self.cfg.get("instance_url", "")).rstrip("/")
        if not base:
            raise ChannelError(f"{self.id}: instance_url is required")
        return f"{base}/api/now/table/{self.cfg.get('table', 'incident')}"

    def open(self, item, group):
        existing = self._ticket(item)
        headers = {"Accept": "application/json"}
        if existing:
            sys_id = existing.split("|")[0]
            self.http("PATCH", f"{self.table_url}/{sys_id}", auth=self._auth(), headers=headers,
                      json={"work_notes": f"Still no logs: {detail(item, group)}"})
            return
        crit = item.get("criticality") or "medium"
        body = {
            "short_description": _summary(item)[:160],
            "description": _description(item, group),
            "urgency": SNOW_URGENCY.get(crit, "3"),
            "impact": SNOW_IMPACT.get(crit, "2"),
            **({"assignment_group": self.cfg["assignment_group"]} if self.cfg.get("assignment_group") else {}),
            **({"caller_id": self.cfg["caller_id"]} if self.cfg.get("caller_id") else {}),
            **(self.cfg.get("fields") or {}),
        }
        result = self.http("POST", self.table_url, auth=self._auth(), headers=headers, json=body).json()
        record = result.get("result", {})
        self._remember(item, f"{record.get('sys_id')}|{record.get('number')}")
        self.logger.info(f"Created {record.get('number')} for {item.get('device_name')}")

    def close(self, item):
        existing = self._ticket(item)
        if not existing:
            return
        sys_id = existing.split("|")[0]
        self.http("PATCH", f"{self.table_url}/{sys_id}", auth=self._auth(), headers={"Accept": "application/json"},
                  json={"state": str(self.cfg.get("resolve_state", "6")),
                        "close_code": self.cfg.get("close_code", "Solved (Permanently)"),
                        "close_notes": "SIEM Pulse: logs are flowing again."})
        self._remember(item, None)


class JiraChannel(_PerDeviceChannel):
    type_name = "jira"

    def _request_kwargs(self):
        token = self.secret("token_secret", "JIRA_API_TOKEN")
        if not token:
            raise ChannelError(f"{self.id}: {self.cfg.get('token_secret', 'JIRA_API_TOKEN')} is not set")
        headers = {"Accept": "application/json"}
        if str(self.cfg.get("auth", "basic")).lower() == "bearer":
            headers["Authorization"] = f"Bearer {token}"
            return {"headers": headers}
        email = self.secret("email_secret", "JIRA_EMAIL")
        if not email:
            raise ChannelError(f"{self.id}: {self.cfg.get('email_secret', 'JIRA_EMAIL')} is not set")
        return {"headers": headers, "auth": (email, token)}

    @property
    def api(self):
        base = str(self.cfg.get("base_url", "")).rstrip("/")
        if not base:
            raise ChannelError(f"{self.id}: base_url is required")
        return f"{base}/rest/api/2"

    def _comment(self, key, text):
        self.http("POST", f"{self.api}/issue/{key}/comment", json={"body": text}, **self._request_kwargs())

    def open(self, item, group):
        existing = self._ticket(item)
        if existing:
            self._comment(existing, f"Still no logs: {detail(item, group)}")
            return
        client_label = re.sub(r"[^a-z0-9]+", "-", str(item.get("client_name") or "na").lower()).strip("-")
        fields = {
            "project": {"key": self.cfg.get("project_key", "SOC")},
            "summary": _summary(item)[:250],
            "description": _description(item, group),
            "issuetype": {"name": self.cfg.get("issue_type", "Task")},
            "labels": list(self.cfg.get("labels", ["siem-pulse"])) + [client_label],
            **(self.cfg.get("fields") or {}),
        }
        priority_map = self.cfg.get("priority_map") or {}
        if item.get("criticality") in priority_map:
            fields["priority"] = {"name": priority_map[item["criticality"]]}
        result = self.http("POST", f"{self.api}/issue", json={"fields": fields}, **self._request_kwargs()).json()
        self._remember(item, result.get("key"))
        self.logger.info(f"Created {result.get('key')} for {item.get('device_name')}")

    def close(self, item):
        key = self._ticket(item)
        if not key:
            return
        self._comment(key, "SIEM Pulse: logs are flowing again.")
        if self.cfg.get("resolve_transition_id"):
            self.http("POST", f"{self.api}/issue/{key}/transitions",
                      json={"transition": {"id": str(self.cfg["resolve_transition_id"])}},
                      **self._request_kwargs())
        self._remember(item, None)
