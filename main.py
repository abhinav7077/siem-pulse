# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""Run SIEM Pulse from a source checkout: `python main.py --help`.
When installed with pip, use the `siem-pulse` command instead."""

from siem_pulse.cli import main

if __name__ == "__main__":
    main()
