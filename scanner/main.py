"""Full pipeline: start Flask target, run garak + pyrit probes, aggregate, report."""

import subprocess
import sys
import time

from scanner.aggregator import aggregate_findings
from scanner.garak_runner import run_garak_probes
from scanner.pyrit_runner import run_pyrit_probes
from scanner.reporter import generate_report

TARGET_URL = "http://localhost:5000/chat"
VENV_PYTHON = sys.executable


def main():
    flask_proc = subprocess.Popen(
        [VENV_PYTHON, "target/app.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(2)

        garak_findings = run_garak_probes(TARGET_URL)
        pyrit_findings = run_pyrit_probes(TARGET_URL)

        all_findings = garak_findings + pyrit_findings
        aggregated = aggregate_findings(all_findings)
        paths = generate_report(aggregated)

        meta = aggregated["meta"]
        print("Scan complete.")
        print(f"Total findings: {meta['total']}")
        print(
            f"Critical: {meta['critical']} | High: {meta['high']} | "
            f"Medium: {meta['medium']} | Low: {meta['low']}"
        )
        print(f"Report: {paths['md']}")
        print(f"JSON: {paths['json']}")

        sys.exit(1 if meta["critical"] > 0 else 0)

    finally:
        flask_proc.terminate()
        try:
            flask_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            flask_proc.kill()


if __name__ == "__main__":
    main()
