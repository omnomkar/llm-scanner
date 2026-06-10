#!/usr/bin/env python3
"""Standalone integration test: spins up the Flask target and runs PyRIT probes."""

import json
import subprocess
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from scanner.pyrit_runner import run_pyrit_probes

VENV_PYTHON = str(__import__("pathlib").Path(__file__).parent.parent / "venv" / "bin" / "python")
TARGET_SCRIPT = str(__import__("pathlib").Path(__file__).parent.parent / "target" / "app.py")
TARGET_URL = "http://localhost:5000/chat"


def main():
    flask_proc = subprocess.Popen(
        [VENV_PYTHON, TARGET_SCRIPT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(2)

        print("=" * 60)
        print("Running PyRIT probes against", TARGET_URL)
        print("=" * 60)

        findings = run_pyrit_probes(TARGET_URL)

        print("=" * 60)
        print(f"Total findings: {len(findings)}")
        print("=" * 60)

        if findings:
            print(json.dumps(findings, indent=2))
        else:
            print("No findings detected.")
    finally:
        flask_proc.terminate()
        flask_proc.wait()


if __name__ == "__main__":
    main()
