# Wazuh

```yaml
siem:
  wazuh:
    base_url: "https://wazuh.example.com:55000"
```

Credentials: an **API** user (`WAZUH_USER` / `WAZUH_PASS`), not a dashboard user. SIEM Pulse authenticates (`/security/user/authenticate`), pages through `/agents` and uses each agent's `lastKeepAlive`. Agent `000` (the manager) is skipped.

`lastKeepAlive` shows the agent is connected; it does not prove every log type arrives. Devices sending syslog to Wazuh without an agent are better checked through the indexer with the [Elastic/OpenSearch](elastic.md) connector.
