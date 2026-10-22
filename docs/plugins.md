# Plugins

Add SIEM connectors or alert channels without changing SIEM Pulse: publish a Python package that registers them under an entry-point group.

## A connector

```python
# siem_pulse_graylog/__init__.py
from siem_pulse.siem_clients.base_client import InventoryClient, parse_timestamp

class GraylogClient(InventoryClient):
    config_key = "graylog"                       # settings live under siem.graylog

    def __init__(self, config, base_url=None, auth_ref=None):
        super().__init__(config, base_url=base_url, auth_ref=auth_ref)
        self.base_url = self.platform_cfg.get("base_url", "").rstrip("/")
        self.token = self.credential("GRAYLOG_TOKEN")   # honours auth_ref + secrets provider

    def _fetch_inventory(self):
        data = self._json(self._request("GET", f"{self.base_url}/api/sources",
                                        auth=(self.token, "token")), "Graylog")
        return [{"name": name, "identifier": name, "last_seen": parse_timestamp(ts)}
                for name, ts in data.get("sources", {}).items()]
```

```toml
# pyproject.toml of the plugin
[project.entry-points."siem_pulse.connectors"]
graylog = "siem_pulse_graylog:GraylogClient"
```

After `pip install siem-pulse-graylog`, use `siem_platform: graylog` in the inventory. `self._request()` gives you retries, TLS settings, rate limits and per-tenant credentials checks; `InventoryClient` gives bulk lookups, mock mode and `--reconcile`. Implement `get_last_log_time()` directly (subclass `BaseSIEMClient`) for per-device APIs, and `_fetch_metrics()` with `supports_metrics = True` for deeper detection.

## A channel

```python
from siem_pulse.channels.base import Channel, plain_text

class MattermostChannel(Channel):
    type_name = "mattermost"

    def send(self, batch):
        url = self.secret("webhook_secret", "MATTERMOST_WEBHOOK_URL")
        self.http("POST", url, json={"text": plain_text(batch)})
        return [i["device_key"] for i in batch.issues]
```

```toml
[project.entry-points."siem_pulse.channels"]
mattermost = "siem_pulse_mattermost:MattermostChannel"
```

Then `alerting.channels.team_chat: {type: mattermost}`.
