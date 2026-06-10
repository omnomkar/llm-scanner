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


def classify_severity(category):
    pass


def aggregate_findings(*sources):
    pass
