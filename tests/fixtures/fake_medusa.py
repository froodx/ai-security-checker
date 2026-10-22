#!/usr/bin/env python3
"""Small MEDUSA-compatible process used only by the wrapper tests."""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path


def main() -> int:
    arguments = sys.argv[1:]
    if arguments == ["--version"]:
        print("MEDUSA vTEST")
        return 0
    if not arguments or arguments[0] != "scan":
        return 2
    target = Path(arguments[1])
    output = Path(arguments[arguments.index("--output") + 1])
    output.mkdir(parents=True, exist_ok=True)
    if "slow" in target.name:
        signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(143))
        time.sleep(30)
    report = {
        "scan_summary": {"missing_linters": ["fixture-linter"]},
        "findings": [
            {
                "scanner": "fixture",
                "file": str(target / "agent.py"),
                "line": 7,
                "severity": "HIGH",
                "confidence": "HIGH",
                "issue": "Shell input may reach a command.",
                "rule_id": "FIX001",
                "code": "token=fixture-secret-value",
            }
        ],
    }
    (output / "medusa-scan-20000101-000000.json").write_text(json.dumps(report), encoding="utf-8")
    if "--format" in arguments and "html" in arguments:
        (output / "medusa-scan-20000101-000000.html").write_text("<p>fixture</p>", encoding="utf-8")
    print(f"scanned {target}")
    return int(os.environ.get("FAKE_MEDUSA_EXIT", "0"))


if __name__ == "__main__":
    raise SystemExit(main())
