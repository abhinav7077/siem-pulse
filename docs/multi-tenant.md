# Multi-client setups & secrets

## Tenants

Each device row can point at its own SIEM:

| Inventory column | Effect |
|------------------|--------|
| `api_endpoint` | Overrides that platform's `base_url` |
| `auth_ref` | Loads `siem.<platform>.tenants.<auth_ref>` overrides and that tenant's credentials |

```yaml
siem:
  qradar:
    max_concurrent_requests: 5
    tenants:
      acme:   {base_url: "https://qradar.acme.example/api", verify_ssl: "/etc/ssl/acme-ca.pem"}
      globex: {base_url: "https://qradar.globex.example/api", requests_per_second: 2}
```

One client object exists per tenant (platform + endpoint + auth_ref), with its own connections, bulk cache and rate limits.

**A tenant never falls back to the default credentials.** If `ACME_QRADAR_SEC_TOKEN` is missing, Acme's devices report an error and nothing is sent — one client's token can never reach another client's SIEM.

## Where credentials come from

```yaml
secrets:
  provider: env            # env | vault | aws | azure
  fallback_to_env: true
```

| Provider | Secret location | Notes |
|----------|-----------------|-------|
| `env` | `<AUTH_REF>_<NAME>`, e.g. `ACME_QRADAR_SEC_TOKEN` (`.env` loaded automatically) | default |
| `vault` | KV v2 at `<mount>/siem-pulse/<tenant>`, key `<NAME>` | `VAULT_ADDR`, `VAULT_TOKEN`, optional namespace |
| `aws` | Secrets Manager JSON secret `siem-pulse/<tenant>`, key `<NAME>` | `pip install boto3` |
| `azure` | Key Vault secret `<TENANT>-<NAME>` with `-` for `_` | `pip install azure-identity azure-keyvault-secrets` |

Devices without `auth_ref` use the tenant `default`. Channel secrets (SMTP, webhooks, PagerDuty…) and dashboard tokens use the same provider.
