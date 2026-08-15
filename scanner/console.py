"""Structured console output for the scanner pipeline.

This module is presentation only. It never decides anything about severity,
ordering or counts -- it renders what the aggregator already produced. Two
consequences worth keeping in mind when editing:

  * The severity/source rank maps are imported from scanner.aggregator and the
    category labels from scanner.reporter, deliberately. Re-declaring them here
    would create two sources of truth that silently drift, so that the console
    table and the Markdown report could disagree about ordering or naming.
  * Colour is opt-out three ways (see ``color_enabled``), so piping output to a
    file or a CI log always yields clean ASCII.
"""

import os
import sys

from scanner.aggregator import _SEVERITY_RANK, _SOURCE_RANK
from scanner.reporter import _CATEGORY_LABEL

# Total rendered width of the findings table, in characters.
TABLE_WIDTH = 100

_COL_SEVERITY = 8   # "CRITICAL"
_COL_CATEGORY = 21  # "System Prompt Leakage"
_COL_SOURCE = 6     # "SOURCE" / "garak" / "pyrit"
_COL_GAP = 2
# Whatever is left over after the fixed columns and the three inter-column gaps.
_COL_PROMPT = TABLE_WIDTH - (
    _COL_SEVERITY + _COL_CATEGORY + _COL_SOURCE + 3 * _COL_GAP
)

SEVERITY_ORDER = ("critical", "high", "medium", "low")

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_SEVERITY_ANSI = {
    "critical": "\033[1;31m",  # bold red
    "high": "\033[31m",        # red
    "medium": "\033[33m",      # yellow
    "low": "\033[32m",         # green
}

# Set by configure(); None means "not configured yet, fall back to auto-detect".
_no_color_override = False


def configure(no_color=False):
    """Apply CLI-level output settings. Call once, early, from main()."""
    global _no_color_override
    _no_color_override = bool(no_color)


def color_enabled():
    """Return True if ANSI colour should be emitted.

    Colour is suppressed when any of the following holds:

      * ``configure(no_color=True)`` was called (the ``--no-color`` flag),
      * the ``NO_COLOR`` environment variable is set to a non-empty value
        (https://no-color.org),
      * stdout is not a TTY -- i.e. output is being piped or redirected, as in
        CI logs, so escape codes would just be noise in the captured text.
    """
    if _no_color_override:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _wrap(text, code):
    """Wrap ``text`` in an ANSI ``code`` if colour is on, else return it as-is."""
    if not code or not color_enabled():
        return text
    return f"{code}{text}{_RESET}"


def severity_color(text, severity):
    """Colour ``text`` according to ``severity``."""
    return _wrap(text, _SEVERITY_ANSI.get(severity))


def format_duration(seconds):
    """Render an elapsed time as e.g. "3s", "4m12s", "1h02m03s"."""
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def _flush(line=""):
    """Print and flush immediately.

    Flushing matters here: stdout is block-buffered when it is not a TTY (CI),
    and garak's inherited stderr is not buffered by us at all. Without the
    flush, phase banners would appear in the log out of order relative to the
    subprocess output they bracket.
    """
    print(line, flush=True)


def phase_start(message):
    """Announce the start of a pipeline phase."""
    _flush(_wrap(f">> {message}", _BOLD))


def phase_done(name, hits, elapsed):
    """Announce the end of a phase, with hit count and elapsed time."""
    noun = "hit" if hits == 1 else "hits"
    _flush(_wrap(f"   {name} complete — {hits} {noun} in {format_duration(elapsed)}", _DIM))


def note(message):
    """Emit a secondary, non-structural line."""
    _flush(_wrap(f"   {message}", _DIM))


def _one_line(text, width):
    """Collapse whitespace and hard-truncate ``text`` to ``width`` characters.

    garak's DAN prompts are multi-line and thousands of characters long; without
    the whitespace collapse a single finding would shred the table layout.
    """
    if not text:
        return ""
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= width:
        return collapsed
    if width <= 3:
        return collapsed[:width]
    return collapsed[: width - 3] + "..."


def _sort_key(finding):
    """Same ordering the aggregator applies: critical first, pyrit before garak."""
    return (
        _SEVERITY_RANK.get(finding.get("severity"), 3),
        _SOURCE_RANK.get(finding.get("source", "garak"), 1),
    )


def findings_table(findings, max_rows=25, more_hint=None):
    """Print the findings table.

    ``findings`` arrives already sorted by the aggregator; it is re-sorted here
    with the identical key so the table is correct on its own terms too. Python's
    sort is stable, so this is a no-op on already-ordered input.

    ``max_rows`` caps the printed rows (0 or None prints every row). A full garak
    run produces several hundred findings, which is unreadable in a terminal --
    the elided rows are still present in full in both report files, and
    ``more_hint`` is appended to the elision line to point at them.
    """
    if not findings:
        _flush()
        _flush(_wrap("Findings", _BOLD))
        note("none")
        return

    rows = sorted(findings, key=_sort_key)
    shown = rows if not max_rows else rows[:max_rows]

    header = (
        "SEVERITY".ljust(_COL_SEVERITY)
        + " " * _COL_GAP
        + "CATEGORY".ljust(_COL_CATEGORY)
        + " " * _COL_GAP
        + "SOURCE".ljust(_COL_SOURCE)
        + " " * _COL_GAP
        + "PROMPT"
    )
    rule = (
        "-" * _COL_SEVERITY
        + " " * _COL_GAP
        + "-" * _COL_CATEGORY
        + " " * _COL_GAP
        + "-" * _COL_SOURCE
        + " " * _COL_GAP
        + "-" * _COL_PROMPT
    )

    _flush()
    _flush(_wrap("Findings", _BOLD))
    _flush(_wrap(header, _BOLD))
    _flush(rule)

    for finding in shown:
        severity = finding.get("severity", "low")
        category = _CATEGORY_LABEL.get(
            finding.get("category", ""), finding.get("category", "")
        )
        source = finding.get("source", "")
        prompt = finding.get("prompt", "")

        # Pad before colouring: ANSI escapes are zero-width on screen but count
        # toward len(), so ljust() on an already-coloured string mis-aligns.
        severity_cell = severity_color(
            severity.upper().ljust(_COL_SEVERITY), severity
        )
        _flush(
            severity_cell
            + " " * _COL_GAP
            + _one_line(category, _COL_CATEGORY).ljust(_COL_CATEGORY)
            + " " * _COL_GAP
            + _one_line(source, _COL_SOURCE).ljust(_COL_SOURCE)
            + " " * _COL_GAP
            + _one_line(prompt, _COL_PROMPT)
        )

    hidden = len(rows) - len(shown)
    if hidden > 0:
        suffix = f" — full detail in {more_hint}" if more_hint else ""
        note(f"... and {hidden} more{suffix}")


def summary_block(meta):
    """Print aligned severity counts plus the total."""
    label_width = max(len(s) for s in SEVERITY_ORDER) + 1  # + 1 for "Critical"
    label_width = max(label_width, len("Total"))
    count_width = max(len(str(meta.get(k, 0))) for k in SEVERITY_ORDER)
    count_width = max(count_width, len(str(meta.get("total", 0))))

    _flush()
    _flush(_wrap("Summary", _BOLD))
    for key in SEVERITY_ORDER:
        label = key.capitalize().ljust(label_width)
        count = str(meta.get(key, 0)).rjust(count_width)
        _flush("  " + severity_color(f"{label}  {count}", key))
    _flush("  " + "-" * (label_width + 2 + count_width))
    _flush(
        "  "
        + _wrap(
            "Total".ljust(label_width) + "  " + str(meta.get("total", 0)).rjust(count_width),
            _BOLD,
        )
    )


def source_breakdown(meta):
    """Print the garak vs pyrit finding counts."""
    sources = meta.get("sources", {}) or {}
    if not sources:
        return

    label_width = max(len(name) for name in sources)
    count_width = max(len(str(count)) for count in sources.values())

    _flush()
    _flush(_wrap("Sources", _BOLD))
    # pyrit before garak, matching the aggregator's ordering.
    for name in sorted(sources, key=lambda n: _SOURCE_RANK.get(n, 1)):
        _flush(f"  {name.ljust(label_width)}  {str(sources[name]).rjust(count_width)}")


def report_paths(paths):
    """Print where the Markdown and JSON reports were written."""
    _flush()
    _flush(_wrap("Reports", _BOLD))
    _flush(f"  Markdown  {paths.get('md', '')}")
    _flush(f"  JSON      {paths.get('json', '')}")


def gate_line(critical):
    """Print the final severity-gate verdict and return the exit code it implies.

    The returned code is advisory -- main() owns the actual exit contract. This
    only guarantees the printed line and the real exit status agree.
    """
    _flush()
    if critical > 0:
        noun = "finding" if critical == 1 else "findings"
        _flush(
            severity_color(
                f"GATE: {critical} critical {noun} — exiting 1", "critical"
            )
        )
        return 1
    _flush(severity_color("GATE: no critical findings — exiting 0", "low"))
    return 0
