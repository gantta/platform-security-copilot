# platform-security-copilot

A LangChain agent system that triages CVEs and Kubernetes manifests, pulls remediation guidance from your runbooks, asks a human before anything risky, and writes a remediation report.

## Run

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

1. Copy `.env` and set `ANTHROPIC_API_KEY`. Optional: `PSC_MODEL`, `PSC_FAST_MODEL`, and LangSmith tracing vars.
2. Install dependencies:

```bash
uv sync
```

3. Run a module from the repo root (as a module, so `psc` imports resolve):

```bash
uv run python -m psc.m1_triage_agent
```

Scans `data/manifests/payments-api.yaml` and looks up Log4Shell (`CVE-2021-44228`), then prints a structured JSON report.

```bash
uv run python -m psc.rag
```

Searches the local runbooks for how to fix a privileged container and prints the top hits. Embeddings stay on the machine; no model API key is required.

```bash
uv run python -m psc.m3_workflow
```

Scans `payments-api.yaml`, drafts a remediation plan, and pauses for a scripted human review that accepts the risk on `PSC-K8S-005`. Prints the report, then runs a second thread that suppresses the accepted rule.

```bash
uv run python -m psc.m4_supervisor
```

Reviews `payments-api.yaml` plus xz 5.6.0 (`CVE-2024-3094`) by delegating to specialist agents, streams each step, then drafts a Jira ticket title for the top item on the same thread.

```bash
uv run python -m psc.m5_deep_audit
```

Audits every manifest, researches Log4Shell and the xz backdoor, and writes the report under `audit_ws/`.

```bash
uv run python evals/run_evals.py
```

Creates the `psc-triage-v1` LangSmith dataset if it does not exist, then evaluates two triage-prompt variants. Needs `LANGSMITH_API_KEY` in addition to the model key.

`uv run python main.py` only prints a hello message — it is not the agent.
