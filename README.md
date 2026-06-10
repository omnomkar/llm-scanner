# llm-scanner

> LLM security scanner using Garak & PyRIT to probe endpoints for
> jailbreaks, prompt injection, and data leakage.

## What it does

llm-scanner probes LLM API endpoints for security vulnerabilities using two complementary frameworks. Garak (NVIDIA) runs a library of ~5500 automated probes across categories like DAN jailbreaks, prompt injection, and spam/toxicity detection. PyRIT (Microsoft) executes targeted red-teaming attack strategies including jailbreak escalation, system prompt leakage, and direct injection. Findings are deduplicated, severity-classified, and output as JSON and Markdown reports, with the CI pipeline exiting 1 when critical vulnerabilities are detected.

## Architecture

```
vulnerable Flask target
       ↓
┌─────────────────────┐
│   garak_runner.py   │ ← ~5500 automated probes (DAN, promptinject, av_spam)
│   pyrit_runner.py   │ ← targeted attacks (jailbreak, leakage, injection)
└─────────────────────┘
       ↓
aggregator.py  ← deduplication, severity classification
       ↓
reporter.py    ← JSON + Markdown output
       ↓
GitHub Actions ← CI/CD with severity gating (exits 1 on critical)
```

## Vulnerability Categories Detected

| Category | Severity | Detection Method | Example |
|---|---|---|---|
| Jailbreak | Critical | Garak DAN probes + PyRIT | Model bypasses safety guardrails |
| System Prompt Leakage | Critical | PyRIT malformed payloads | System prompt + SSN exposed via error handler |
| Prompt Injection | High | Garak promptinject + PyRIT | Injected instructions echoed or followed |
| Toxicity | Low | Garak av_spam_scanning | Known bad signatures not filtered |

## Findings Schema

```json
{
  "id": "uuid4",
  "source": "garak | pyrit",
  "category": "jailbreak | prompt_injection | system_prompt_leakage | ...",
  "severity": "critical | high | medium | low",
  "prompt": "attack prompt used",
  "response": "model response",
  "rationale": "why this is classified at this severity"
}
```

## Running Locally

```bash
git clone https://github.com/omnomkar/llm-scanner
cd llm-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python scanner/main.py
```

## CI/CD

Every push to `master` triggers the GitHub Actions workflow. Unit tests run first in the `test` job, if they fail, the scan is skipped. Once tests pass, the `scan` job starts the vulnerable Flask target, runs the full scanner pipeline against it, and uploads the Markdown report as a workflow artifact. The pipeline exits 1 if critical findings are detected, causing the job to show red in the Actions UI, this is intentional behavior, acting as a hard security gate that blocks merges when critical vulnerabilities exist.

## Tech Stack

- **Garak 0.15.1** (NVIDIA) — automated LLM probe library
- **PyRIT 0.14.0** (Microsoft) — red-teaming attack framework
- **Flask** — deliberately vulnerable target endpoint
- **pytest** — unit tests for aggregation logic
- **GitHub Actions** — CI/CD with severity gating
- **Docker** — containerized target for reproducible scanning
