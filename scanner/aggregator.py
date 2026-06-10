"""Aggregates findings from garak/pyrit runners into the common finding schema
and assigns severity classifications."""

SEVERITY_BY_CATEGORY = {
    "jailbreak": "critical",
    "system_prompt_leakage": "critical",
    "prompt_injection": "high",
    "data_leakage": "high",
    "indirect_injection": "medium",
    "toxicity": "low",
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SOURCE_RANK = {"pyrit": 0, "garak": 1}

CATEGORIES = [
    "jailbreak",
    "prompt_injection",
    "system_prompt_leakage",
    "data_leakage",
    "indirect_injection",
    "toxicity",
]


def classify_severity(category):
    return SEVERITY_BY_CATEGORY.get(category, "low")


def aggregate_findings(findings):
    """Deduplicate, classify, sort, and count a flat list of finding dicts.

    Two findings are duplicates if they share the same category and identical
    prompt. Duplicates are collapsed to the higher-severity entry; if severities
    are equal the pyrit entry is preferred (human-crafted > automated).
    """
    deduped = {}
    for f in findings:
        severity = f.get("severity") or classify_severity(f.get("category", ""))
        f = dict(f, severity=severity)

        key = (f.get("category"), f.get("prompt"))
        if key not in deduped:
            deduped[key] = f
        else:
            existing = deduped[key]
            existing_rank = _SEVERITY_RANK.get(existing["severity"], 3)
            new_rank = _SEVERITY_RANK.get(f["severity"], 3)
            if new_rank < existing_rank:
                deduped[key] = f
            elif new_rank == existing_rank:
                if _SOURCE_RANK.get(f.get("source", "garak"), 1) < _SOURCE_RANK.get(
                    existing.get("source", "garak"), 1
                ):
                    deduped[key] = f

    deduplicated = list(deduped.values())

    # critical → high → medium → low; within same severity pyrit before garak
    deduplicated.sort(
        key=lambda f: (
            _SEVERITY_RANK.get(f.get("severity"), 3),
            _SOURCE_RANK.get(f.get("source", "garak"), 1),
        )
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in deduplicated:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1

    sources = {"garak": 0, "pyrit": 0}
    for f in deduplicated:
        src = f.get("source", "")
        if src in sources:
            sources[src] += 1

    categories = {c: 0 for c in CATEGORIES}
    for f in deduplicated:
        cat = f.get("category", "")
        if cat in categories:
            categories[cat] += 1

    return {
        "meta": {
            "total": len(deduplicated),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "sources": sources,
            "categories": categories,
        },
        "findings": deduplicated,
    }
