# llm-scanner

> LLM security scanner using Garak & PyRIT to probe endpoints for
> jailbreaks, prompt injection, and data leakage.

## What it does

llm-scanner probes LLM API endpoints for security vulnerabilities using two complementary layers. Garak (NVIDIA) runs a library of ~5500 automated probes across categories like DAN jailbreaks, prompt injection, and spam/toxicity detection. A second red-teaming layer executes targeted attacks — jailbreak escalation, system prompt leakage, and direct injection — written directly against the target's HTTP API using PyRIT's documented attack categories (see [Red-teaming layer](#red-teaming-layer) for why the PyRIT library itself is not a dependency). Findings are deduplicated, severity-classified, and output as JSON and Markdown reports, with the CI pipeline exiting 1 when critical vulnerabilities are detected.

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

## Red-teaming layer

The red-teaming attack layer uses PyRIT's attack taxonomy but not the PyRIT library. The PyRIT 0.13.0 API was audited against this project's requirements and found unusable for driving a plain REST endpoint:

| Symbol | Status in 0.13.0 |
|---|---|
| `pyrit.orchestrator.RedTeamingOrchestrator` | module `pyrit.orchestrator` does not exist |
| `pyrit.models.PromptRequestPiece` | class removed |
| `pyrit.prompt_target.HTTPTarget` | imports, but requires `CentralMemory` infrastructure to be configured before it can be instantiated |

Rather than stand up PyRIT's memory/orchestrator infrastructure to send four categories of HTTP POST, the attack layer in `scanner/pyrit_runner.py` implements the same documented attack categories — jailbreak, system prompt leakage, prompt injection, and error-path information disclosure — directly against the target's HTTP API with `requests`. Findings from this layer are labelled `source: "pyrit"` to distinguish them from Garak's.

This keeps the dependency surface to `requests` and makes each attack prompt and its hit criterion explicit and reviewable in one file.

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
python -m scanner.main
```

Options:

| Flag | Effect |
|---|---|
| `--no-color` | Disable ANSI colour. Also disabled automatically when stdout is not a TTY, or when `NO_COLOR` is set. |
| `--max-rows N` | Cap the console findings table at `N` rows (default 25; `0` prints all). Every finding always appears in full in the reports. |

The scanner exits 1 when any critical finding is detected, 0 otherwise.

## CI/CD

Every push to `master` triggers the GitHub Actions workflow. Unit tests run first in the `test` job; if they fail, the scan is skipped. Once tests pass, the `scan` job starts the vulnerable Flask target, runs the full scanner pipeline against it, and uploads the Markdown report as a workflow artifact.

The scanner exits 1 whenever it finds a critical vulnerability — that is the security gate, and against a real target it is what blocks a merge. The target in CI is *deliberately* vulnerable, so exit 1 is the expected, correct outcome. The workflow therefore asserts on it rather than tripping over it: the scan step runs with `continue-on-error: true`, and a following step fails the job if the scanner did **not** exit 1.

The result is a workflow that goes green because the gate fired as designed, and red if detection ever regresses or the target stops being vulnerable. The run log shows the gate firing either way.

## Tech Stack

- **Garak 0.15.1** (NVIDIA) — automated LLM probe library
- **PyRIT attack categories** (Microsoft) — taxonomy only; the 0.13.0 library API was audited and found unusable for a plain REST target, so the attack layer is implemented directly over HTTP (see [Red-teaming layer](#red-teaming-layer))
- **requests** — HTTP client for the red-teaming attack layer
- **Flask** — deliberately vulnerable target endpoint
- **pytest** — unit tests for aggregation logic
- **GitHub Actions** — CI/CD with severity gating
- **Docker** — containerized target for reproducible scanning

## License

MIT — see [LICENSE](LICENSE).
