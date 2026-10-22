# Getting started

## Install

=== "pip"

    ```bash
    pip install siem-pulse          # Python 3.10+
    siem-pulse --init               # writes config.yaml, .env.example, sample_devices.xlsx
    ```

=== "Docker"

    ```bash
    docker run --rm ghcr.io/abhinav7077/siem-pulse:latest --threads 4     # one mock check
    ```

=== "From source"

    ```bash
    git clone https://github.com/abhinav7077/siem-pulse.git && cd siem-pulse
    pip install -e ".[dev]"
    python main.py
    ```

## First run (mock mode)

`config.yaml` starts with `siem.mock_mode: true`, so every command works without credentials:

```bash
siem-pulse --dry-run        # which devices would be checked
siem-pulse                  # one check: console table, CSV in reports/, alerts, history in siem_pulse.db
siem-pulse --reconcile      # inventory vs. what the SIEM knows
siem-pulse --dashboard      # web dashboard on http://127.0.0.1:8080
```

## Connect a real SIEM

1. Put your devices in the inventory — see [Inventory](inventory.md).
2. Copy `.env.example` to `.env` and add the credentials for your SIEM ([per-SIEM guides](siems/index.md)). `.env` is loaded automatically.
3. Set `siem.mock_mode: false` and the SIEM's `base_url` in `config.yaml`.
4. Run `siem-pulse --dry-run`, then `siem-pulse`.
5. Configure [alerts](alerting.md), then run on a schedule: `siem-pulse --schedule` (or see [Deployment](deployment.md)).

## Command reference

| Command | What it does |
|---------|--------------|
| `siem-pulse` | One check cycle |
| `--schedule` | Repeat every `scheduler.interval_minutes` |
| `--dashboard` | Web dashboard (with `--schedule`: in the same process) |
| `--siem NAME` / `--client NAME` | Limit a run to one SIEM and/or client |
| `--dry-run` | List devices without calling any SIEM |
| `--reconcile` | Unmonitored sources and devices the SIEM has never seen |
| `--snooze DEVICE --until 4h --reason TEXT` | Silence a device; `--unsnooze`, `--list-snoozes` |
| `--digest` | Send the open-issues digest now |
| `--check-heartbeat` | Alert and exit 2 if no run finished recently |
| `--list-clients`, `--list-siems` | Summaries of the inventory |
| `--init` | Write starter files into the current folder |
| `--config`, `--env-file`, `--device-file`, `--threads` | Paths and parallelism |
