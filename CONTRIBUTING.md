# Contributing to SIEM Pulse

Thanks for helping improve SIEM Pulse. Contributions of all sizes are welcome:
bug reports, docs fixes, new SIEM connectors and new alert channels.

## Getting started

```bash
git clone https://github.com/abhinav7077/siem-pulse.git
cd siem-pulse
pip install -e ".[dev]"
python main.py          # runs in mock mode, no credentials needed
ruff check . && python -m pytest
```

Docs: `pip install -r docs/requirements.txt && mkdocs serve`.

## Where to help

See [ROADMAP.md](ROADMAP.md). Good first contributions:

- A new SIEM connector (Graylog, Google SecOps, LogRhythm, ArcSight…) — see
  [docs/plugins.md](docs/plugins.md); bulk APIs subclass `InventoryClient`.
- A new alert channel (Mattermost, Google Chat, Zendesk…).
- Confirming a connector against a real SIEM version and fixing defaults
  (Seceon especially).
- Recipes for the generic REST connector.

## Pull requests

1. Create a branch from `main`.
2. Keep each pull request focused on one change.
3. Never commit credentials, `.env` files or real customer data. Use mock mode
   and fake device names/IPs in examples and tests.
4. Describe what changed and how you tested it.
5. If you change `config.yaml`, `.env.example` or `sample_devices.xlsx`, copy
   them into `siem_pulse/templates/` too (a test checks they match).
6. Add a line to `CHANGELOG.md` under *Unreleased*.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security
issues privately — see [SECURITY.md](SECURITY.md).

## Releasing (maintainers)

1. Update `siem_pulse/__version__`, `CHANGELOG.md`, `CITATION.cff` and the Helm
   chart's `version` / `appVersion`.
2. Merge to `main`, then `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The Release workflow tests, publishes to PyPI, creates the GitHub release and
   pushes `ghcr.io/abhinav7077/siem-pulse:X.Y.Z`.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
