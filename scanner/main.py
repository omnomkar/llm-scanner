"""Full pipeline: start Flask target, run garak + pyrit probes, aggregate, report."""

import argparse
import subprocess
import sys
import time

from scanner import console
from scanner.aggregator import aggregate_findings
from scanner.garak_runner import PROBE_FAMILIES, PROBES, run_garak_probes
from scanner.pyrit_runner import run_pyrit_probes
from scanner.reporter import generate_report

TARGET_URL = "http://localhost:5000/chat"
VENV_PYTHON = sys.executable

# How long to give the Flask target to bind its port before probing starts.
TARGET_BOOT_SECONDS = 2


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "Probe an LLM endpoint for jailbreaks, prompt injection and data "
            "leakage. Exits 1 when any critical finding is detected."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help=(
            "Disable ANSI colour in console output. Colour is also disabled "
            "automatically when stdout is not a TTY or NO_COLOR is set."
        ),
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=25,
        metavar="N",
        help=(
            "Maximum findings to print in the console table (default: 25; "
            "use 0 for all). Every finding always appears in the reports."
        ),
    )
    parser.add_argument(
        "--no-target",
        action="store_true",
        help=(
            "Do not start (or stop) the Flask target; attach to one that is "
            "already listening at the target URL. Use this when something "
            "else owns the target's lifecycle, such as CI."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Print every non-hit attack probe with its prompt and the "
            "target's response. Off by default. Transport errors are always "
            "printed regardless of this flag."
        ),
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    console.configure(no_color=args.no_color)

    # None means we did not start the target and must not shut it down either.
    flask_proc = None
    target_started = time.monotonic()

    if args.no_target:
        console.phase_start("Attaching to already-running target...")
    else:
        console.phase_start("Starting vulnerable target...")
        flask_proc = subprocess.Popen(
            [VENV_PYTHON, "target/app.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    try:
        if flask_proc is None:
            console.note(f"using existing target at {TARGET_URL}")
        else:
            time.sleep(TARGET_BOOT_SECONDS)
            console.note(
                f"target listening at {TARGET_URL} "
                f"({console.format_duration(time.monotonic() - target_started)})"
            )

        console.phase_start(
            f"Running garak probes ({len(PROBES)} probes across "
            f"{len(PROBE_FAMILIES)} families)..."
        )
        garak_started = time.monotonic()
        garak_findings = run_garak_probes(TARGET_URL)
        console.phase_done(
            "garak", len(garak_findings), time.monotonic() - garak_started
        )

        console.phase_start("Running PyRIT-style attack probes...")
        pyrit_started = time.monotonic()
        pyrit_findings = run_pyrit_probes(TARGET_URL, verbose=args.verbose)
        console.phase_done(
            "pyrit", len(pyrit_findings), time.monotonic() - pyrit_started
        )

        console.phase_start("Aggregating and writing reports...")
        all_findings = garak_findings + pyrit_findings
        aggregated = aggregate_findings(all_findings)
        paths = generate_report(aggregated)

        meta = aggregated["meta"]
        console.note(
            f"{len(all_findings)} raw findings deduplicated to {meta['total']}"
        )

        console.findings_table(
            aggregated["findings"],
            max_rows=args.max_rows,
            more_hint=paths["md"],
        )
        console.summary_block(meta)
        console.source_breakdown(meta)
        console.report_paths(paths)
        console.gate_line(meta["critical"])

        sys.exit(1 if meta["critical"] > 0 else 0)

    finally:
        # Only tear down a target this process started; under --no-target the
        # caller owns it.
        if flask_proc is not None:
            flask_proc.terminate()
            try:
                flask_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                flask_proc.kill()


if __name__ == "__main__":
    main()
