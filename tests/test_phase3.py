# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Phase 3: history, state-aware alerts, thresholds, suppression, routing, channels."""

import email
import email.header
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from siem_pulse import cli
from siem_pulse.alert_policy import AlertBatch, classify, digest_due, route
from siem_pulse.alerting import AlertManager
from siem_pulse.channels import base as channel_base
from siem_pulse.channels import build_channels
from siem_pulse.channels.summary import SLACK_TEXT_LIMIT, EmailChannel, SlackChannel
from siem_pulse.excel_reader import ExcelReader
from siem_pulse.log_checker import LogChecker, device_key
from siem_pulse.state_store import StateStore
from siem_pulse.suppression import apply_suppression, in_weekly_window, parse_until
from tests.conftest import FakeHTTP, FakeResponse

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)  # a Saturday


def result(name, status="stale", client="Acme", criticality="medium", **extra):
    device = {"device_name": name, "ip_address": "10.0.0.1", "siem_platform": "qradar", "client_name": client}
    return {**device, "device_key": device_key(device), "status": status, "criticality": criticality,
            "last_log_time": "2026-10-23 08:00:00 UTC", "hours_since_last_log": 28.0,
            "threshold_hours": 24.0, "checked_at": NOW.isoformat(), **extra}


@pytest.fixture
def store():
    s = StateStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def http(monkeypatch):
    fake = FakeHTTP()
    monkeypatch.setattr(channel_base.requests, "request", fake)
    return fake


# ─── Thresholds and inventory columns ────────────────────────────────────────

def test_threshold_priority():
    checker = LogChecker(threshold_hours=24, criticality_thresholds={"critical": 1, "low": 72})
    assert checker.threshold_for({"criticality": "critical"}) == 1
    assert checker.threshold_for({"criticality": "critical", "threshold_hours": 6}) == 6
    assert checker.threshold_for({}) == 24
    assert checker.threshold_for({"criticality": "low"}) == 72


def test_new_inventory_columns_are_parsed(tmp_path):
    path = tmp_path / "d.csv"
    path.write_text(
        "device_name,ip_address,siem_platform,threshold_hours,criticality,snooze_until,"
        "device_type,expected_log_types\n"
        "fw,10.0.0.1,qradar,6,Critical,2026-11-01,Firewall,traffic;system\n"
        "sw,10.0.0.2,qradar,abc,urgent,not-a-date,,\n"
    )
    fw, sw = ExcelReader(str(path)).load_devices()
    assert fw["threshold_hours"] == 6 and fw["criticality"] == "critical"
    assert fw["snooze_until"] == datetime(2026, 11, 1, tzinfo=timezone.utc)
    assert fw["device_type"] == "firewall" and fw["expected_log_types"] == ["traffic", "system"]
    assert "threshold_hours" not in sw and "criticality" not in sw and "snooze_until" not in sw


# ─── State-aware classification ───────────────────────────────────────────────

def run_cycle(store, results, config, now):
    previous = store.get_states(r["device_key"] for r in results)
    batch = classify(results, previous, config, now=now)
    store.update_states(results, previous)
    store.mark_alerted(i["device_key"] for i in batch.issues)
    return batch


def test_new_then_quiet_then_reminder_then_recovered(store):
    config = {"alerting": {"repeat_after_hours": 24}}
    now = datetime.now(tz=timezone.utc)   # the store stamps alerts with the real clock
    b1 = run_cycle(store, [result("fw")], config, now)
    assert [i["device_name"] for i in b1.new] == ["fw"]

    b2 = run_cycle(store, [result("fw")], config, now + timedelta(hours=1))
    assert b2.is_empty() and [i["device_name"] for i in b2.ongoing] == ["fw"]

    b3 = classify([result("fw")], store.get_states(), config, now=now + timedelta(hours=25))
    assert [i["device_name"] for i in b3.reminders] == ["fw"]

    b4 = run_cycle(store, [result("fw", status="healthy")], config, now + timedelta(hours=26))
    assert [i["device_name"] for i in b4.recovered] == ["fw"]

    b5 = run_cycle(store, [result("fw", status="healthy")], config, now + timedelta(hours=27))
    assert b5.is_empty()


def test_undelivered_issue_stays_new(store):
    config = {}
    previous = store.get_states()
    batch = classify([result("fw")], previous, config, now=NOW)
    store.update_states([result("fw")], previous)        # not marked alerted: delivery failed
    again = classify([result("fw")], store.get_states(), config, now=NOW)
    assert batch.new and again.new


def test_every_run_mode_repeats(store):
    config = {"alerting": {"mode": "every_run"}}
    run_cycle(store, [result("fw")], config, NOW)
    b2 = run_cycle(store, [result("fw")], config, NOW + timedelta(minutes=5))
    assert [i["device_name"] for i in b2.reminders] == ["fw"]


def test_suppressed_issue_not_alerted_until_suppression_ends(store):
    r = result("fw", suppressed="maintenance: patching")
    b1 = run_cycle(store, [r], {}, NOW)
    assert not b1.new and b1.ongoing
    b2 = run_cycle(store, [result("fw")], {}, NOW + timedelta(hours=1))
    assert [i["device_name"] for i in b2.new] == ["fw"]


def test_history_is_recorded(store):
    rid = store.start_run("ALL devices")
    store.finish_run(rid, [result("fw"), result("sw", status="healthy")], 1.5)
    run = store.last_run()
    assert run["total"] == 2 and run["stale"] == 1 and run["healthy"] == 1
    assert len(store.run_results(rid)) == 2


# ─── Suppression ──────────────────────────────────────────────────────────────

def test_weekly_window_overnight():
    window = {"days": ["sat"], "start": "22:00", "end": "04:00"}
    assert in_weekly_window(window, datetime(2026, 10, 24, 23, 0, tzinfo=timezone.utc))      # Sat 23:00
    assert in_weekly_window(window, datetime(2026, 10, 25, 3, 0, tzinfo=timezone.utc))       # Sun 03:00
    assert not in_weekly_window(window, datetime(2026, 10, 25, 5, 0, tzinfo=timezone.utc))
    assert not in_weekly_window(window, datetime(2026, 10, 23, 23, 0, tzinfo=timezone.utc))  # Fri


def test_apply_suppression_sources(store):
    config = {"maintenance_windows": [
        {"name": "Acme patching", "match": {"client_name": "acme"},
         "start": "2026-10-24T10:00:00Z", "end": "2026-10-24T14:00:00Z"},
    ]}
    snoozed = result("snoozed-box", client="Globex")
    store.snooze(snoozed["device_key"], "snoozed-box", datetime.now(tz=timezone.utc) + timedelta(hours=2), "RMA")
    results = [
        result("in-window"),
        result("col-snooze", client="Globex", snooze_until=NOW + timedelta(days=1)),
        snoozed,
        result("normal", client="Globex"),
    ]
    count = apply_suppression(results, config, store.active_snoozes(), now=NOW)
    assert count == 3
    reasons = {r["device_name"]: r["suppressed"] for r in results}
    assert reasons["in-window"] == "maintenance: Acme patching"
    assert "inventory" in reasons["col-snooze"]
    assert "RMA" in reasons["snoozed-box"]
    assert reasons["normal"] is None


def test_parse_until():
    assert parse_until("4h", now=NOW) == NOW + timedelta(hours=4)
    assert parse_until("2d", now=NOW) == NOW + timedelta(days=2)
    assert parse_until("2026-10-30T08:00", now=NOW) == datetime(2026, 10, 30, 8, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        parse_until("soonish")


# ─── Routing ──────────────────────────────────────────────────────────────────

def test_routes_per_client_and_criticality():
    config = {"alerting": {
        "default_channels": ["soc"],
        "routes": [
            {"match": {"criticality": "critical"}, "channels": ["pager"], "continue": True},
            {"match": {"client_name": "Acme*"}, "channels": ["acme"]},
        ],
    }}
    batch = AlertBatch(new=[result("a1", client="Acme Corp"), result("a2", client="Acme Corp", criticality="critical"),
                            result("g1", client="Globex")])
    parts = route(batch, config)
    names = {cid: sorted(i["device_name"] for i in b.new) for cid, b in parts.items()}
    assert names == {"pager": ["a2"], "acme": ["a1", "a2"], "soc": ["g1"]}


def test_legacy_email_slack_blocks_become_default_channels():
    config = {"alerting": {"email": {"enabled": True, "recipients": ["x@y"]}, "slack": {"enabled": False}}}
    assert list(build_channels(config)) == ["email"]
    assert list(route(AlertBatch(new=[result("fw")]), config)) == ["email"]


def test_digest_due():
    config = {"alerting": {"digest": {"enabled": True, "time": "08:00"}}}
    morning = datetime(2026, 10, 24, 9, 0, tzinfo=timezone.utc)
    assert digest_due(config, None, morning)
    assert not digest_due(config, "2026-10-24T08:30:00+00:00", morning)
    assert digest_due(config, "2026-10-23T08:30:00+00:00", morning)
    assert not digest_due(config, None, datetime(2026, 10, 24, 7, 0, tzinfo=timezone.utc))


# ─── Channels ─────────────────────────────────────────────────────────────────

def test_slack_splits_long_alerts(http, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    http.add("POST", "hooks.slack.test", FakeResponse(200, text="ok"))
    batch = AlertBatch(new=[result(f"device-with-a-long-name-{i:04d}", client=f"Client {i % 7}")
                            for i in range(2000)])
    channel = SlackChannel("slack", {}, {})
    messages = channel.build_messages(batch)
    assert len(messages) > 1
    for message in messages:
        assert len(message["blocks"]) <= 50
        for block in message["blocks"]:
            if block["type"] == "section":
                assert len(block["text"]["text"]) <= 3000
    assert sum(b["text"]["text"].count("•") for m in messages for b in m["blocks"] if b["type"] == "section") == 2000
    keys = channel.send(batch)
    assert len(keys) == 2000 and len(http.calls) == len(messages)
    assert SLACK_TEXT_LIMIT < 3000


def test_email_has_plain_text_and_html(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, user, password):
            sent["login"] = (user, password)

        def sendmail(self, sender, recipients, message):
            sent["message"] = message
    monkeypatch.setattr("siem_pulse.channels.summary.smtplib.SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    channel = EmailChannel("email", {"smtp_server": "smtp.test", "sender": "soc@test", "recipients": ["a@test"]}, {})
    channel.send(AlertBatch(new=[result("fw")], recovered=[result("sw", status="healthy")]))
    assert sent["login"] == ("soc@test", "pw") and sent["tls"]
    assert "text/plain" in sent["message"] and "text/html" in sent["message"]
    parsed = email.message_from_string(sent["message"])
    assert "1 new, 1 recovered" in str(email.header.make_header(email.header.decode_header(parsed["Subject"])))
    text = parsed.get_payload()[0].get_payload(decode=True).decode()
    assert "fw (10.0.0.1)" in text and "Recovered" in text


def test_teams_and_webhook(http, monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://teams.test/hook")
    monkeypatch.setenv("SOAR_HMAC", "s3cret")
    http.add("POST", "teams.test", FakeResponse(202, text=""))
    http.add("POST", "soar.test", FakeResponse(200, {}))
    config = {"alerting": {"default_channels": ["teams", "soar"], "channels": {
        "teams": {"type": "teams"},
        "soar": {"type": "webhook", "url": "https://soar.test/in", "hmac_secret": "SOAR_HMAC"},
    }}}
    outcome = AlertManager(config).dispatch(AlertBatch(new=[result("fw")]))
    assert outcome == {"teams": True, "soar": True}
    card = http.calls[0]["json"]["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    hook = http.calls[1]
    expected = "sha256=" + hmac.new(b"s3cret", hook["data"], hashlib.sha256).hexdigest()
    assert hook["headers"]["X-SiemPulse-Signature"] == expected
    assert json.loads(hook["data"])["new"][0]["device_name"] == "fw"


def test_pagerduty_trigger_and_resolve(http, monkeypatch, store):
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "rk")
    http.add("POST", "events.pagerduty.com", FakeResponse(202, {"status": "success"}))
    config = {"alerting": {"default_channels": ["pd"], "channels": {"pd": {"type": "pagerduty"}}}}
    manager = AlertManager(config, store)
    manager.dispatch(AlertBatch(new=[result("fw", criticality="critical")]))
    manager.dispatch(AlertBatch(recovered=[result("fw", status="healthy")]))
    trigger, resolve = (c["json"] for c in http.calls)
    assert trigger["event_action"] == "trigger" and trigger["payload"]["severity"] == "critical"
    assert resolve["event_action"] == "resolve" and resolve["dedup_key"] == trigger["dedup_key"]


def test_opsgenie_create_and_close(http, monkeypatch):
    monkeypatch.setenv("OPSGENIE_API_KEY", "ok")
    http.add("POST", "/close", FakeResponse(202, {}))
    http.add("POST", "/v2/alerts", FakeResponse(202, {}))
    config = {"alerting": {"default_channels": ["og"], "channels": {"og": {"type": "opsgenie"}}}}
    manager = AlertManager(config)
    manager.dispatch(AlertBatch(new=[result("fw", criticality="high")]))
    manager.dispatch(AlertBatch(recovered=[result("fw", status="healthy")]))
    create, close = http.calls
    assert create["json"]["priority"] == "P2" and create["headers"]["Authorization"] == "GenieKey ok"
    assert close["url"].endswith(f"/v2/alerts/{create['json']['alias']}/close")


def test_servicenow_ticket_lifecycle_without_duplicates(http, monkeypatch, store):
    monkeypatch.setenv("SERVICENOW_USER", "u")
    monkeypatch.setenv("SERVICENOW_PASS", "p")
    http.add("POST", "/api/now/table/incident", FakeResponse(201, {"result": {"sys_id": "abc", "number": "INC001"}}))
    http.add("PATCH", "/api/now/table/incident/abc", FakeResponse(200, {"result": {}}))
    config = {"alerting": {"default_channels": ["snow"], "channels": {
        "snow": {"type": "servicenow", "instance_url": "https://acme.service-now.test", "assignment_group": "SOC"}}}}
    fw = result("fw")
    store.update_states([fw], {})
    manager = AlertManager(config, store)
    manager.dispatch(AlertBatch(new=[fw]))
    manager.dispatch(AlertBatch(reminders=[fw]))
    manager.dispatch(AlertBatch(recovered=[result("fw", status="healthy")]))
    methods = [(c["method"], c["url"].rsplit("/", 1)[-1]) for c in http.calls]
    assert methods == [("POST", "incident"), ("PATCH", "abc"), ("PATCH", "abc")]
    assert http.calls[0]["json"]["assignment_group"] == "SOC"
    assert "work_notes" in http.calls[1]["json"]
    assert http.calls[2]["json"]["state"] == "6"
    assert store.get_ticket(fw["device_key"], "snow") is None


def test_jira_issue_comment_transition(http, monkeypatch, store):
    monkeypatch.setenv("JIRA_EMAIL", "bot@test")
    monkeypatch.setenv("JIRA_API_TOKEN", "t")
    http.add("POST", "/comment", FakeResponse(201, {}))
    http.add("POST", "/transitions", FakeResponse(204, text=""))
    http.add("POST", "/rest/api/2/issue", FakeResponse(201, {"key": "SOC-7"}))
    config = {"alerting": {"default_channels": ["jira"], "channels": {
        "jira": {"type": "jira", "base_url": "https://acme.atlassian.test", "project_key": "SOC",
                 "resolve_transition_id": 31}}}}
    fw = result("fw")
    store.update_states([fw], {})
    manager = AlertManager(config, store)
    manager.dispatch(AlertBatch(new=[fw]))
    manager.dispatch(AlertBatch(new=[fw]))          # already has a ticket: comment, not a duplicate
    manager.dispatch(AlertBatch(recovered=[result("fw", status="healthy")]))
    urls = [c["url"].replace("https://acme.atlassian.test/rest/api/2", "") for c in http.calls]
    assert urls == ["/issue", "/issue/SOC-7/comment", "/issue/SOC-7/comment", "/issue/SOC-7/transitions"]
    assert http.calls[0]["auth"] == ("bot@test", "t")
    assert http.calls[0]["json"]["fields"]["project"]["key"] == "SOC"


def test_failing_channel_does_not_block_others(http, monkeypatch, store):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://teams.test/hook")
    http.add("POST", "teams.test", FakeResponse(500, text="boom"))
    http.add("POST", "soar.test", FakeResponse(200, {}))
    config = {"alerting": {"default_channels": ["teams", "soar"], "channels": {
        "teams": {"type": "teams"}, "soar": {"type": "webhook", "url": "https://soar.test/in"}}}}
    fw = result("fw")
    store.update_states([fw], {})
    assert AlertManager(config, store).dispatch(AlertBatch(new=[fw])) == {"teams": False, "soar": True}
    assert store.get_states()[fw["device_key"]]["alerted"] == 1


# ─── End to end through the CLI ───────────────────────────────────────────────

def test_run_check_alerts_only_on_changes(tmp_path, http, monkeypatch):
    http.add("POST", "soar.test", FakeResponse(200, {}))
    inventory = tmp_path / "devices.csv"
    inventory.write_text("device_name,ip_address,siem_platform,client_name\n"
                         "fw,10.0.0.1,qradar,Acme\nsw,10.0.0.2,qradar,Acme\n")
    config = {
        "siem": {"mock_mode": True, "mock_seed": 1},
        "logic": {"threshold_hours": 0.01},     # everything is stale
        "state": {"path": str(tmp_path / "state.db")},
        "reporting": {"output_dir": str(tmp_path / "reports")},
        "alerting": {"default_channels": ["soar"],
                     "channels": {"soar": {"type": "webhook", "url": "https://soar.test/in"}}},
    }
    logger = cli.setup_logging({"logging": {"file": ""}})
    first = cli.run_check(config, str(inventory), logger, num_threads=2)
    second = cli.run_check(config, str(inventory), logger, num_threads=2)
    assert len(first["batch"].new) == 2
    assert second["batch"].is_empty()
    assert len(http.calls) == 1
