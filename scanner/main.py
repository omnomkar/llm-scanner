"""Full pipeline: start Flask target, run garak + pyrit probes, aggregate, report."""

import argparse
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

from scanner import console
from scanner.aggregator import aggregate_findings
from scanner.garak_runner import PROBE_FAMILIES, PROBES, run_garak_probes
from scanner.pyrit_runner import run_pyrit_probes
from scanner.reporter import generate_report

# --target name -> (chat endpoint, script that serves it).
TARGETS = {
    "mock": ("http://localhost:5000/chat", "target/app.py"),
    "rag": ("http://localhost:5001/chat", "target/rag_app.py"),
}
VENV_PYTHON = sys.executable

# How long to give the Flask target to bind its port before probing starts.
TARGET_BOOT_SECONDS = 2

# The RAG target loads an embedding model before it binds, so instead of a
# fixed sleep it is polled until the port opens, up to this long.
RAG_BOOT_TIMEOUT_SECONDS = 60


def _positive_int(value):
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def wait_for_port(proc, url, timeout):
    """Poll until ``url``'s port accepts connections. Return an error or None.

    Fails fast if ``proc`` exits first: the target's output goes to DEVNULL, so
    a crash at startup (missing API key, database down) would otherwise look
    like a slow boot until the timeout.
    """
    parsed = urlparse(url)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return f"target exited with code {proc.returncode} during startup"
        try:
            with socket.create_connection((parsed.hostname, parsed.port), timeout=1):
                return None
        except OSError:
            time.sleep(0.5)
    return f"target did not open port {parsed.port} within {timeout}s"


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
        "--target",
        choices=sorted(TARGETS),
        default="mock",
        help=(
            "Which target to scan (default: mock). 'rag' scans the live-LLM "
            "RAG target on port 5001, adds the indirect prompt injection and "
            "RAG data leakage attacks, and skips garak, since every probe is "
            "a billed Claude API call."
        ),
    )
    parser.add_argument(
        "--repeat",
        type=_positive_int,
        default=1,
        metavar="N",
        help=(
            "Send each attack prompt N times (default: 1). A live LLM is "
            "nondeterministic, so repeats give a hit rate instead of a single "
            "yes/no."
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
    target_url, target_script = TARGETS[args.target]
    is_rag = args.target == "rag"

    # None means we did not start the target and must not shut it down either.
    flask_proc = None
    target_started = time.monotonic()

    if args.no_target:
        console.phase_start("Attaching to already-running target...")
    else:
        console.phase_start(
            "Starting RAG target..." if is_rag else "Starting vulnerable target..."
        )
        flask_proc = subprocess.Popen(
            [VENV_PYTHON, target_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    try:
        if flask_proc is None:
            console.note(f"using existing target at {target_url}")
        else:
            if is_rag:
                error = wait_for_port(flask_proc, target_url, RAG_BOOT_TIMEOUT_SECONDS)
                if error:
                    console.note(
                        f"{error}; run `python {target_script}` directly to see why"
                    )
                    sys.exit(2)
            else:
                time.sleep(TARGET_BOOT_SECONDS)
            console.note(
                f"target listening at {target_url} "
                f"({console.format_duration(time.monotonic() - target_started)})"
            )

        if is_rag:
            # Each garak probe would be a billed Claude call, ~5500 of them.
            console.phase_start("Skipping garak probes (rag target: API cost)")
            garak_findings = []
        else:
            console.phase_start(
                f"Running garak probes ({len(PROBES)} probes across "
                f"{len(PROBE_FAMILIES)} families)..."
            )
            garak_started = time.monotonic()
            garak_findings = run_garak_probes(target_url)
            console.phase_done(
                "garak", len(garak_findings), time.monotonic() - garak_started
            )

        repeat_note = f", each sent {args.repeat}x" if args.repeat > 1 else ""
        console.phase_start(f"Running PyRIT-style attack probes{repeat_note}...")
        pyrit_started = time.monotonic()
        probe_stats = {}
        pyrit_findings = run_pyrit_probes(
            target_url,
            verbose=args.verbose,
            target=args.target,
            repeat=args.repeat,
            stats=probe_stats,
        )
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
        if is_rag:
            console.hit_rates(probe_stats)
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
