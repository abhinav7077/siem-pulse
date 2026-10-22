# Security Policy

SIEM Pulse handles SIEM credentials and security telemetry, so we take
vulnerabilities seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through
[GitHub's private vulnerability reporting](https://github.com/abhinav7077/siem-pulse/security/advisories/new)
(Security → Report a vulnerability).

Include what you found, how to reproduce it, and the impact you expect. We aim
to acknowledge reports within 5 working days and to agree a disclosure date
with you once a fix is ready.

## Supported versions

Security fixes go into the latest release.

## Hardening notes for users

- Keep credentials in `.env` (never committed) or a secrets manager (`secrets.provider`).
- Use `verify_ssl: true` or a CA bundle path for every SIEM in production.
- Give SIEM API users read-only permissions.
- Expose the dashboard only with `dashboard.users` configured, ideally behind TLS (reverse proxy / ingress).
- Use per-client `auth_ref` credentials on multi-tenant setups; SIEM Pulse never falls back to another tenant's credentials.
