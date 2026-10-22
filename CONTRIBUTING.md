# Contributing to SIEM Pulse

Thanks for helping improve SIEM Pulse. Contributions of all sizes are welcome:
bug reports, docs fixes, new SIEM connectors and new alert channels.

## Getting started

```bash
git clone https://github.com/abhinav7077/siem-pulse.git
cd siem-pulse
pip install -r requirements.txt
python main.py          # runs in mock mode, no credentials needed
```

## Where to help

See [ROADMAP.md](ROADMAP.md). Good first contributions:

- A new SIEM connector (Splunk, Sentinel, Elastic, Wazuh). Copy an existing
  client in `modules/siem_clients/`, implement `get_last_log_time()`, and
  register it in `factory.py`.
- A new alert channel (Microsoft Teams, PagerDuty).
- Tests for existing modules.

## Pull requests

1. Create a branch from `main`.
2. Keep each pull request focused on one change.
3. Never commit credentials, `.env` files or real customer data. Use mock mode
   and fake device names/IPs in examples and tests.
4. Describe what changed and how you tested it.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
