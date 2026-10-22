# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
alerting.py
===========
Sends alerts for stale/error devices via:
  - Email (SMTP with TLS)
  - Slack webhook (optional)

Supports filter context in subject lines so analysts know which
scope triggered the alert (all devices, one SIEM, or one client).

Credentials are always loaded from environment variables.

Environment variables:
    SMTP_PASSWORD       — Password for SMTP sender account
    SLACK_WEBHOOK_URL   — Slack Incoming Webhook URL
"""

import logging
import os
import smtplib
import json
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class AlertManager:
    """Dispatches alerts via configured channels (email, Slack)."""

    def __init__(self, config: dict):
        self.config = config
        self.alert_cfg = config.get("alerting", {})

    def send_alert(
        self,
        stale_devices: List[Dict[str, Any]],
        error_devices: List[Dict[str, Any]],
        filter_siem: Optional[str] = None,
        filter_client: Optional[str] = None,
    ):
        """Send alerts through all configured channels."""
        if not stale_devices and not error_devices:
            logger.info("No stale/error devices — no alert sent.")
            return

        total = len(stale_devices) + len(error_devices)
        scope_label = self._scope_label(filter_siem, filter_client)
        logger.info(
            f"Sending alerts: {total} issue(s) | {len(stale_devices)} stale | "
            f"{len(error_devices)} errors | Scope: {scope_label}"
        )

        if self.alert_cfg.get("email", {}).get("enabled", False):
            self._send_email(stale_devices, error_devices, filter_siem, filter_client)

        if self.alert_cfg.get("slack", {}).get("enabled", False):
            self._send_slack(stale_devices, error_devices, filter_siem, filter_client)

    # ─── Email ────────────────────────────────────────────────────────────────

    def _send_email(
        self,
        stale: List[Dict[str, Any]],
        errors: List[Dict[str, Any]],
        filter_siem: Optional[str],
        filter_client: Optional[str],
    ):
        cfg = self.alert_cfg.get("email", {})
        smtp_password = os.environ.get("SMTP_PASSWORD", "")

        if not smtp_password:
            logger.warning(
                "SMTP_PASSWORD not set — skipping email. "
                "Set the SMTP_PASSWORD environment variable."
            )
            return

        sender = cfg.get("sender", "soc-monitor@example.com")
        recipients = cfg.get("recipients", [])
        if not recipients:
            logger.warning("No email recipients configured — skipping.")
            return

        scope_label = self._scope_label(filter_siem, filter_client)
        now_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        subject = (
            f"{cfg.get('subject_prefix', '[SOC ALERT]')} "
            f"{len(stale)} Stale | {len(errors)} Error — "
            f"{scope_label} — {now_str}"
        )

        html_body = self._build_html_email(stale, errors, scope_label, now_str)
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(cfg["smtp_server"], cfg.get("port", 587)) as server:
                if cfg.get("use_tls", True):
                    server.starttls()
                server.login(sender, smtp_password)
                server.sendmail(sender, recipients, msg.as_string())
            logger.info(f"Alert email sent to: {recipients}")
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP auth failed — check SMTP_PASSWORD.")
        except Exception as e:
            logger.error(f"Email send failed: {e}")

    def _build_html_email(
        self,
        stale: List[Dict],
        errors: List[Dict],
        scope_label: str,
        now_str: str,
    ) -> str:
        def rows(devices: List[Dict], row_class: str, last_col_key: str) -> str:
            if not devices:
                return (
                    f'<tr><td colspan="5" style="text-align:center;color:#888;">'
                    f'None</td></tr>'
                )
            return "".join(
                f"""<tr class="{row_class}">
                    <td>{d.get('device_name', '')}</td>
                    <td>{d.get('client_name', 'N/A')}</td>
                    <td>{d.get('siem_platform', '').upper()}</td>
                    <td>{d.get('ip_address', '')}</td>
                    <td>{d.get(last_col_key, 'N/A')}</td>
                </tr>"""
                for d in sorted(devices, key=lambda x: (x.get("client_name") or "", x.get("device_name") or ""))
            )

        return f"""
        <html><head><style>
            body {{ font-family: Arial, sans-serif; font-size: 14px; color: #333; }}
            h2 {{ color: #c0392b; }}
            h3 {{ margin-top: 24px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
            th {{ background: #2c3e50; color: white; padding: 8px; text-align: left; font-size: 13px; }}
            td {{ padding: 6px 8px; border-bottom: 1px solid #ddd; font-size: 13px; }}
            .stale {{ background: #fdf2f2; }}
            .error {{ background: #fef9e7; }}
            .footer {{ font-size: 12px; color: #999; margin-top: 24px; border-top: 1px solid #eee; padding-top: 8px; }}
            .scope {{ background: #eaf4fb; padding: 6px 12px; border-left: 4px solid #2980b9;
                      font-size: 13px; margin-bottom: 12px; }}
        </style></head><body>
            <h2>🚨 SOC Log Health Alert</h2>
            <div class="scope">Scope: <strong>{scope_label}</strong> — {now_str}</div>

            <h3 style="color:#e74c3c;">❌ Stale Devices ({len(stale)})</h3>
            <table>
                <tr><th>Device</th><th>Client</th><th>SIEM</th>
                    <th>IP Address</th><th>Last Log Time</th></tr>
                {rows(stale, 'stale', 'last_log_time')}
            </table>

            <h3 style="color:#f39c12;">⚠️ Error Devices ({len(errors)})</h3>
            <table>
                <tr><th>Device</th><th>Client</th><th>SIEM</th>
                    <th>IP Address</th><th>Error</th></tr>
                {rows(errors, 'error', 'error')}
            </table>

            <p class="footer">
                SOC Log Health Monitor — investigate log sources and restore log flow.<br>
                Run <code>python main.py --client "{scope_label}" --dry-run</code>
                to preview affected devices.
            </p>
        </body></html>
        """

    # ─── Slack ────────────────────────────────────────────────────────────────

    def _send_slack(
        self,
        stale: List[Dict[str, Any]],
        errors: List[Dict[str, Any]],
        filter_siem: Optional[str],
        filter_client: Optional[str],
    ):
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
        if not webhook_url:
            logger.warning(
                "SLACK_WEBHOOK_URL not set — skipping Slack alert."
            )
            return

        now_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        scope_label = self._scope_label(filter_siem, filter_client)

        def fmt_list(devices: List[Dict], key: str) -> str:
            if not devices:
                return "_None_"
            # Group by client
            by_client: Dict[str, list] = {}
            for d in devices:
                by_client.setdefault(d.get("client_name", "N/A"), []).append(d)
            lines = []
            for client, devs in sorted(by_client.items()):
                lines.append(f"*{client}*")
                for d in devs:
                    lines.append(
                        f"  • `{d['device_name']}` [{d.get('siem_platform','').upper()}] "
                        f"{d['ip_address']} — {d.get(key, 'N/A')}"
                    )
            return "\n".join(lines)

        payload = {
            "text": f":rotating_light: SOC Alert — {scope_label} — {now_str}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 SOC Log Health Alert — {scope_label}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*{len(stale)} stale* and *{len(errors)} error* "
                            f"device(s) detected at {now_str}"
                        ),
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*❌ Stale:*\n{fmt_list(stale, 'last_log_time')}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*⚠️ Errors:*\n{fmt_list(errors, 'error')}",
                    },
                },
            ],
        }

        try:
            resp = requests.post(
                webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            logger.info("Slack alert sent.")
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _scope_label(filter_siem: Optional[str], filter_client: Optional[str]) -> str:
        parts = []
        if filter_siem:
            parts.append(f"SIEM={filter_siem.upper()}")
        if filter_client:
            parts.append(f"Client={filter_client}")
        return " | ".join(parts) if parts else "ALL devices"
