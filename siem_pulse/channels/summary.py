# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
Summary channels — one message per batch.

    email    SMTP with HTML + plain-text parts
               {type: email, smtp_server, port: 587, use_tls: true, sender,
                username (default sender), recipients: [...], subject_prefix,
                password_secret: SMTP_PASSWORD, auth: true}
    slack    Incoming webhook; long alerts are split to fit Slack's limits
               {type: slack, webhook_secret: SLACK_WEBHOOK_URL}
    teams    Microsoft Teams workflow / incoming webhook (Adaptive Card)
               {type: teams, webhook_secret: TEAMS_WEBHOOK_URL}
    webhook  Generic JSON POST for SOAR tools (XSOAR, Splunk SOAR, Shuffle, n8n)
               {type: webhook, url: "https://...", url_secret: NAME (instead of url),
                hmac_secret: NAME (adds X-SiemPulse-Signature: sha256=<hex>),
                headers: {..}}
"""

import hashlib
import hmac
import html
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List

from ..alert_policy import AlertBatch
from .base import (
    Channel,
    ChannelError,
    chunk_lines,
    detail,
    device_label,
    jsonable,
    plain_text,
    preview_command,
    sections,
    summary_counts,
    title,
)

SLACK_TEXT_LIMIT = 2900       # Slack section text limit is 3000 characters
SLACK_BLOCKS_PER_MESSAGE = 45  # Slack allows 50 blocks per message
TEAMS_CHARS_PER_MESSAGE = 20000  # Teams payloads are limited to ~28 KB


def _keys(batch: AlertBatch) -> List[str]:
    return [i["device_key"] for i in batch.issues if i.get("device_key")]


# ─── Email ────────────────────────────────────────────────────────────────────

class EmailChannel(Channel):
    type_name = "email"

    def build_html(self, batch: AlertBatch) -> str:
        esc = lambda value: html.escape(str(value if value is not None else "N/A"))
        colours = {"new": "#fdf2f2", "reminders": "#fef9e7", "recovered": "#eafaf1", "ongoing": "#f4f6f7"}
        parts = []
        for group, heading, items in sections(batch):
            rows = "".join(
                f'<tr style="background:{colours[group]}"><td>{esc(i.get("device_name"))}</td>'
                f'<td>{esc(i.get("client_name"))}</td><td>{esc(str(i.get("siem_platform") or "").upper())}</td>'
                f'<td>{esc(i.get("ip_address"))}</td><td>{esc(i.get("criticality"))}</td>'
                f'<td>{esc(detail(i, group))}</td></tr>'
                for i in items
            )
            parts.append(
                f"<h3>{esc(heading)} ({len(items)})</h3><table>"
                "<tr><th>Device</th><th>Client</th><th>SIEM</th><th>IP Address</th>"
                f"<th>Criticality</th><th>Details</th></tr>{rows}</table>"
            )
        return f"""<html><head><style>
            body {{ font-family: Arial, sans-serif; font-size: 14px; color: #333; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
            th {{ background: #2c3e50; color: white; padding: 8px; text-align: left; font-size: 13px; }}
            td {{ padding: 6px 8px; border-bottom: 1px solid #ddd; font-size: 13px; }}
            .scope {{ background: #eaf4fb; padding: 6px 12px; border-left: 4px solid #2980b9; }}
            .footer {{ font-size: 12px; color: #999; margin-top: 24px; border-top: 1px solid #eee; }}
        </style></head><body>
            <h2>{esc(title(batch))}</h2>
            <div class="scope">Scope: <strong>{esc(batch.scope)}</strong> — {esc(batch.time_label)}</div>
            {''.join(parts)}
            <p class="footer">SIEM Pulse — investigate log sources and restore log flow.<br>
            Run <code>{esc(preview_command(batch.scope))}</code> to preview affected devices.</p>
        </body></html>"""

    def send(self, batch: AlertBatch) -> List[str]:
        cfg = self.cfg
        recipients = cfg.get("recipients") or []
        if not recipients:
            raise ChannelError(f"{self.id}: no recipients configured")
        sender = cfg.get("sender", "siem-pulse@example.com")
        use_auth = cfg.get("auth", True)
        password = self.secret("password_secret", "SMTP_PASSWORD") if use_auth else None
        if use_auth and not password:
            raise ChannelError(f"{self.id}: {cfg.get('password_secret', 'SMTP_PASSWORD')} is not set")

        subject = f"{cfg.get('subject_prefix', '[SOC ALERT]')} {summary_counts(batch)} — {batch.scope}"
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(plain_text(batch, preview_command(batch.scope)), "plain", "utf-8"))
        msg.attach(MIMEText(self.build_html(batch), "html", "utf-8"))

        try:
            with smtplib.SMTP(cfg["smtp_server"], cfg.get("port", 587), timeout=self.timeout) as server:
                if cfg.get("use_tls", True):
                    server.starttls()
                if use_auth:
                    server.login(cfg.get("username", sender), password)
                server.sendmail(sender, recipients, msg.as_string())
        except (smtplib.SMTPException, OSError, KeyError) as e:
            raise ChannelError(f"{self.id}: email send failed: {e}") from e
        self.logger.info(f"Email sent to {recipients}")
        return _keys(batch)


# ─── Slack ────────────────────────────────────────────────────────────────────

def _slack_escape(value: Any) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SlackChannel(Channel):
    type_name = "slack"

    def build_messages(self, batch: AlertBatch) -> List[Dict[str, Any]]:
        header = {"type": "header", "text": {"type": "plain_text", "text": title(batch)[:150]}}
        context = {"type": "context", "elements": [{"type": "mrkdwn", "text": _slack_escape(
            f"{summary_counts(batch)} · {batch.time_label} · preview: {preview_command(batch.scope)}")}]}
        body_blocks = []
        for group, heading, items in sections(batch):
            lines, client = [f"*{_slack_escape(heading)} ({len(items)})*"], None
            for item in items:
                if item.get("client_name") != client:
                    client = item.get("client_name")
                    lines.append(f"*{_slack_escape(client or 'N/A')}*")
                lines.append(f"• `{_slack_escape(device_label(item))}` — {_slack_escape(detail(item, group))}")
            for chunk in chunk_lines(lines, SLACK_TEXT_LIMIT):
                body_blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})

        messages = []
        per_message = SLACK_BLOCKS_PER_MESSAGE - 2
        for start in range(0, max(len(body_blocks), 1), per_message):
            part = body_blocks[start:start + per_message]
            blocks = ([header, context] if start == 0 else []) + part
            suffix = f" (part {start // per_message + 1})" if start else ""
            messages.append({"text": title(batch) + suffix, "blocks": blocks})
        return messages

    def send(self, batch: AlertBatch) -> List[str]:
        url = self.cfg.get("webhook_url") or self.secret("webhook_secret", "SLACK_WEBHOOK_URL")
        if not url:
            raise ChannelError(f"{self.id}: {self.cfg.get('webhook_secret', 'SLACK_WEBHOOK_URL')} is not set")
        messages = self.build_messages(batch)
        for message in messages:
            self.http("POST", url, data=json.dumps(message), headers={"Content-Type": "application/json"})
        self.logger.info(f"Slack alert sent ({len(messages)} message(s))")
        return _keys(batch)


# ─── Microsoft Teams ──────────────────────────────────────────────────────────

class TeamsChannel(Channel):
    type_name = "teams"

    def build_messages(self, batch: AlertBatch) -> List[Dict[str, Any]]:
        lines = []
        for group, heading, items in sections(batch):
            lines.append(f"**{heading} ({len(items)})**")
            lines += [f"- **{device_label(i)}** · {i.get('client_name') or 'N/A'} — {detail(i, group)}"
                      for i in items]
        chunks = chunk_lines(lines, TEAMS_CHARS_PER_MESSAGE) or ["No changes"]
        messages = []
        for n, chunk in enumerate(chunks):
            body = []
            if n == 0:
                body.append({"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True,
                             "text": title(batch)})
                body.append({"type": "TextBlock", "isSubtle": True, "wrap": True,
                             "text": f"{batch.time_label} · preview: `{preview_command(batch.scope)}`"})
            body.append({"type": "TextBlock", "wrap": True, "text": chunk.replace("\n", "\n\n")})
            messages.append({
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                "type": "AdaptiveCard", "version": "1.4", "body": body},
                }],
            })
        return messages

    def send(self, batch: AlertBatch) -> List[str]:
        url = self.cfg.get("webhook_url") or self.secret("webhook_secret", "TEAMS_WEBHOOK_URL")
        if not url:
            raise ChannelError(f"{self.id}: {self.cfg.get('webhook_secret', 'TEAMS_WEBHOOK_URL')} is not set")
        messages = self.build_messages(batch)
        for message in messages:
            self.http("POST", url, json=message)
        self.logger.info(f"Teams alert sent ({len(messages)} message(s))")
        return _keys(batch)


# ─── Generic webhook ──────────────────────────────────────────────────────────

class WebhookChannel(Channel):
    type_name = "webhook"

    @staticmethod
    def payload(batch: AlertBatch) -> Dict[str, Any]:
        fields = ("device_key", "device_name", "ip_address", "client_name", "siem_platform", "criticality",
                  "status", "last_log_time", "hours_since_last_log", "threshold_hours", "error", "since",
                  "suppressed", "findings", "device_type", "auth_ref")
        trim = lambda item: {k: jsonable(item.get(k)) for k in fields if k in item}
        return {
            "source": "siem-pulse",
            "kind": batch.kind,
            "scope": batch.scope,
            "generated_at": batch.generated_at.isoformat(),
            "summary": summary_counts(batch),
            "new": [trim(i) for i in batch.new],
            "reminders": [trim(i) for i in batch.reminders],
            "recovered": [trim(i) for i in batch.recovered],
            "ongoing": [trim(i) for i in batch.ongoing],
        }

    def send(self, batch: AlertBatch) -> List[str]:
        url = self.cfg.get("url") or (self.secret("url_secret", "") if self.cfg.get("url_secret") else None)
        if not url:
            raise ChannelError(f"{self.id}: set url or url_secret")
        body = json.dumps(self.payload(batch), sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json", **(self.cfg.get("headers") or {})}
        if self.cfg.get("hmac_secret"):
            key = self.secret("hmac_secret", "")
            if not key:
                raise ChannelError(f"{self.id}: {self.cfg['hmac_secret']} is not set")
            headers["X-SiemPulse-Signature"] = "sha256=" + hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
        self.http("POST", url, data=body, headers=headers)
        self.logger.info("Webhook delivered")
        return _keys(batch)
