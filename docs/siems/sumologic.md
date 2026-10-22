# Sumo Logic

```yaml
siem:
  sumologic:
    base_url: "https://api.sumologic.com/api"     # your deployment, e.g. https://api.eu.sumologic.com/api
    lookback_hours: 24
    query: "* | max(_receipttime) as last_seen by _sourcehost"
```

Credentials: an access key (`SUMO_ACCESS_ID` / `SUMO_ACCESS_KEY`) for a user that can run searches. SIEM Pulse creates a search job, polls it until `DONE GATHERING RESULTS`, reads the aggregate records and deletes the job. Narrow the query (e.g. `_sourceCategory=network/*`) to reduce scan cost.
