"""Runs Garak probes against a target LLM endpoint and emits findings.

This module drives Garak (https://github.com/NVIDIA/garak) against a REST-based
LLM endpoint (e.g. our deliberately vulnerable target/app.py), then parses the
resulting hit log into the project's common finding schema:

    {
        "id": "uuid4 string",
        "source": "garak",
        "category": "jailbreak | prompt_injection | data_leakage |
                     system_prompt_leakage | indirect_injection | toxicity",
        "severity": "critical | high | medium | low",
        "prompt": "the attack prompt used",
        "response": "the model response",
        "rationale": "why this is classified at this severity",
    }
"""

import glob
import json
import os
import subprocess
import sys
import tempfile
import uuid

# Probe families to run, with their exact garak probe names (confirmed via
# `garak --list_probes -p <family>` against garak 0.15.1).
#
# NOTE: in this version of garak, the probe family historically named
# "knownbadsignatures" was renamed to "av_spam_scanning" (it keeps
# "knownbadsignatures.*" as backwards-compatible *aliases*, but
# `--list_probes -p knownbadsignatures` returns no matches -- the canonical,
# listable names are under `av_spam_scanning`). We use the canonical names so
# `--probes` resolves correctly, and treat both "av_spam_scanning" and
# "knownbadsignatures" as the toxicity family when classifying results.
DAN_PROBES = [
    "dan.Ablation_Dan_11_0",
    "dan.AutoDANCached",
    "dan.DanInTheWild",
]

PROMPTINJECT_PROBES = [
    "promptinject.HijackHateHumans",
    "promptinject.HijackKillHumans",
    "promptinject.HijackLongPrompt",
]

# Canonical successor to "knownbadsignatures"; explicitly run via their full
# names since they are not part of garak's default "active" probe set.
KNOWNBADSIGNATURES_PROBES = [
    "av_spam_scanning.EICAR",
    "av_spam_scanning.GTUBE",
    "av_spam_scanning.GTphish",
]

PROBES = DAN_PROBES + PROMPTINJECT_PROBES + KNOWNBADSIGNATURES_PROBES

# Maps a substring found in a probe name to (category, severity).
PROBE_CLASSIFICATION = [
    ("dan", ("jailbreak", "critical")),
    ("promptinject", ("prompt_injection", "high")),
    ("av_spam_scanning", ("toxicity", "low")),
    ("knownbadsignatures", ("toxicity", "low")),
]

RATIONALE_BY_CATEGORY = {
    "jailbreak": "Garak's {probe} probe got the target to bypass its safety guardrails, indicating a successful jailbreak.",
    "prompt_injection": "Garak's {probe} probe successfully injected an attacker-controlled instruction that the target carried out.",
    "toxicity": "Garak's {probe} probe got the target to emit a known-bad signature without filtering, indicating insufficient output safety scanning.",
}

DEFAULT_RATIONALE = "Garak's {probe} probe registered a hit (score={score}) against the target."


# How long garak should wait for a single response from the target before
# giving up. garak's RestGenerator only retries on rate-limit-style exceptions
# (backoff.on_exception wraps RateLimitHit/GeneratorBackoffTrigger, NOT
# requests.exceptions.ReadTimeout), so any unhandled ReadTimeout crashes the
# whole garak subprocess mid-run and silently truncates the probe queue.
#
# We hit exactly that during development: a full run consistently died ~20%
# into dan.DanInTheWild with "Read timed out". It looked like a target-latency
# problem, but raising this from 10s all the way to 60s did *not* fix it --
# the real cause turned out to be how the test harness (test_garak.py) was
# launching the Flask target: it captured the target's stdout/stderr with
# subprocess.PIPE and never read from the pipe. Flask's debug server logs
# every request, so the unread 64KB OS pipe buffer filled up and the
# single-threaded dev server blocked inside write(), hanging for well over a
# minute -- a classic subprocess deadlock, not a slow-response issue. The
# actual fix lives in test_garak.py (discarding the target's output instead of
# capturing it). 60s is kept here regardless as reasonable headroom for a
# busy single-threaded dev server.
REQUEST_TIMEOUT_SECONDS = 60


def _build_generator_config(target_url):
    """Write a temporary REST generator config for garak's rest.RestGenerator
    pointing at ``target_url``, and return its path.

    The caller is responsible for deleting the file when done.
    """
    config = {
        "rest": {
            "RestGenerator": {
                "uri": target_url,
                "method": "post",
                "headers": {"Content-Type": "application/json"},
                "request_timeout": REQUEST_TIMEOUT_SECONDS,
                "response_json": True,
                "response_json_field": "response",
                "req_template": '{"prompt": "$INPUT"}',
            }
        }
    }

    fd, path = tempfile.mkstemp(prefix="garak_generator_config_", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(config, fh)

    return path


def _classify_probe(probe_name):
    """Return (category, severity) for a garak probe name, based on which
    probe family it belongs to."""
    lowered = probe_name.lower()
    for substring, classification in PROBE_CLASSIFICATION:
        if substring in lowered:
            return classification

    # Shouldn't happen for the probes we run, but fail safe rather than crash.
    return ("jailbreak", "critical")


def _rationale_for(category, probe_name, score):
    template = RATIONALE_BY_CATEGORY.get(category, DEFAULT_RATIONALE)
    return template.format(probe=probe_name, score=score)


def _find_hitlog(report_prefix):
    """Locate the JSONL hit log garak produced for this run.

    Garak writes ``<report_prefix>.hitlog.jsonl`` (a JSONL file containing only
    entries that scored a hit) alongside ``<report_prefix>.report.jsonl`` (the
    full attempt log). We want the hit log -- it's already pre-filtered to
    successful attacks.
    """
    candidates = glob.glob(f"{report_prefix}*.hitlog.jsonl")
    if not candidates:
        return None
    # If multiple matches turn up (e.g. from re-runs), prefer the most recent.
    candidates.sort(key=os.path.getmtime, reverse=True)
    return candidates[0]


def _parse_hitlog(hitlog_path):
    """Parse a garak ``.hitlog.jsonl`` file into our finding schema.

    Each line in the hit log is a JSON object representing a single attempt
    that a detector scored as a hit (``score`` close to/at 1.0). Relevant
    fields (confirmed by inspecting real output from garak 0.15.1):

        {
            "prompt": {"turns": [{"content": {"text": "<attack prompt>"}}]},
            "output": {"text": "<model response>"},
            "score": 1.0,
            "probe": "dan.DanInTheWild",
            ...
        }
    """
    findings = []

    with open(hitlog_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            score = entry.get("score")
            # Only include entries that actually scored a hit.
            if not score:
                continue

            probe_name = entry.get("probe", "")
            category, severity = _classify_probe(probe_name)

            try:
                prompt_text = entry["prompt"]["turns"][0]["content"]["text"]
            except (KeyError, IndexError, TypeError):
                prompt_text = None

            try:
                response_text = entry["output"]["text"]
            except (KeyError, TypeError):
                response_text = None

            findings.append(
                {
                    "id": str(uuid.uuid4()),
                    "source": "garak",
                    "category": category,
                    "severity": severity,
                    "prompt": prompt_text,
                    "response": response_text,
                    "rationale": _rationale_for(category, probe_name, score),
                }
            )

    return findings


def run_garak_probes(target_url, probes=None, report_prefix="findings/garak_scan"):
    """Run garak's dan / promptinject / knownbadsignatures (av_spam_scanning)
    probes against ``target_url`` (a REST chat endpoint) and return a list of
    findings in the project's common schema.

    Parameters
    ----------
    target_url:
        The full URL of the target's chat endpoint, e.g.
        ``"http://localhost:5000/chat"``.
    probes:
        Optional override for the list of garak probe names to run. Defaults
        to the dan / promptinject / av_spam_scanning probes selected for this
        project.
    report_prefix:
        Path prefix (relative to the current working directory, or absolute)
        that garak should write its report/hit-log files under. Defaults to
        ``"findings/garak_scan"``.

    Returns
    -------
    list[dict]
        A list of finding dicts conforming to the common finding schema. If
        garak produced no hits, an empty list is returned.
    """
    probe_names = probes if probes is not None else PROBES

    config_path = _build_generator_config(target_url)

    # garak resolves report_prefix relative to its own data dir unless given
    # an absolute path, so make sure findings/ ends up where we expect.
    abs_report_prefix = os.path.abspath(report_prefix)
    os.makedirs(os.path.dirname(abs_report_prefix), exist_ok=True)

    # Use the same interpreter this code is running under (the project's venv
    # python has garak installed; the system python does not).
    cmd = [
        sys.executable,
        "-m",
        "garak",
        "--target_type",
        "rest.RestGenerator",
        "--generator_option_file",
        config_path,
        "--probes",
        ",".join(probe_names),
        "--report_prefix",
        abs_report_prefix,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print("garak exited with a non-zero status:")
            print("--- stdout ---")
            print(result.stdout)
            print("--- stderr ---")
            print(result.stderr)

        hitlog_path = _find_hitlog(abs_report_prefix)
        if hitlog_path is None:
            print(
                f"No garak hit log found for report prefix '{abs_report_prefix}'. "
                "garak stdout/stderr follow for debugging:"
            )
            print(result.stdout)
            print(result.stderr)
            return []

        return _parse_hitlog(hitlog_path)
    finally:
        try:
            os.remove(config_path)
        except OSError:
            pass
