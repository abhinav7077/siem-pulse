## What does this change?

<!-- One or two sentences. Link the issue it closes, if any: Closes #123 -->

## How was it tested?

- [ ] `ruff check .` and `python -m pytest` pass
- [ ] New behaviour has tests (fake HTTP responses — no real SIEMs, credentials or customer data)
- [ ] Tested against a real SIEM (which one / version):

## Checklist

- [ ] Docs updated (README / `docs/` / `config.yaml` comments) if behaviour or config changed
- [ ] `CHANGELOG.md` entry under *Unreleased*
- [ ] `siem_pulse/templates/` updated if `config.yaml`, `.env.example` or `sample_devices.xlsx` changed
