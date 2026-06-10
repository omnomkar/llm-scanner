"""Standalone end-to-end check for scanner.garak_runner.

Starts the deliberately vulnerable Flask target, runs garak's dan /
promptinject / av_spam_scanning (knownbadsignatures) probes against it via
run_garak_probes(), and prints out what came back so we can confirm the
findings match the project's common schema.

Usage (from the project root, with the venv active or not -- this script
re-execs the target under the venv python explicitly):

    ./venv/bin/python scanner/test_garak.py
"""

import json
import os
import subprocess
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENV_PYTHON = os.path.join(PROJECT_ROOT, "venv", "bin", "python")
TARGET_APP = os.path.join(PROJECT_ROOT, "target", "app.py")
TARGET_URL = "http://localhost:5000/chat"

# Make sure `import scanner.garak_runner` works regardless of cwd.
sys.path.insert(0, PROJECT_ROOT)

from scanner.garak_runner import run_garak_probes  # noqa: E402


def main():
    print(f"Starting Flask target via {VENV_PYTHON} {TARGET_APP} ...")
    # IMPORTANT: do NOT capture Flask's stdout/stderr with subprocess.PIPE
    # unless something actively drains it. Flask's debug-mode dev server logs
    # every single HTTP request ("127.0.0.1 - - [...] POST /chat ... 200 -"),
    # and a full garak run fires well over a thousand sequential requests at
    # it. If that output is piped but never read, the OS pipe buffer (64KB on
    # Linux) fills up and the single-threaded Flask process blocks inside
    # write() -- hanging request handling entirely until something drains the
    # pipe (nothing does), which from garak's side looks exactly like an
    # unresponsive server and raises requests.exceptions.ReadTimeout partway
    # through the run (we hit this firsthand: garak crashed mid-dan.DanInTheWild
    # with "Read timed out (read timeout=60)" even after raising the timeout
    # from 10s to 60s -- the real problem wasn't response latency, it was this
    # classic subprocess deadlock). Discarding the output entirely sidesteps
    # the deadlock without touching target/app.py.
    flask_proc = subprocess.Popen(
        [VENV_PYTHON, TARGET_APP],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        print("Waiting 2 seconds for Flask to boot...")
        time.sleep(2)

        print(f"Running garak probes against {TARGET_URL} ...")
        findings = run_garak_probes(TARGET_URL)

        print(f"\nTotal findings: {len(findings)}")
        print("\nFirst 3 findings:")
        for finding in findings[:3]:
            print(json.dumps(finding, indent=2))

    finally:
        print("\nStopping Flask target...")
        flask_proc.terminate()
        try:
            flask_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            flask_proc.kill()
            flask_proc.wait()
        print("Flask target stopped.")


if __name__ == "__main__":
    main()
