# platform-security-copilot

A LangChain agent system that triages CVEs and Kubernetes manifests, pulls remediation guidance from your runbooks, asks a human before anything risky, and writes a remediation report.

## Run

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

1. Copy `.env` and set `ANTHROPIC_API_KEY`. Optional: `PSC_MODEL`, `PSC_FAST_MODEL`, and LangSmith tracing vars.
2. Install dependencies:

```bash
uv sync
```

3. Run the triage agent from the repo root (as a module, so `psc` imports resolve):

```bash
uv run python -m psc.m1_triage_agent
```

That scans `data/manifests/payments-api.yaml` and looks up Log4Shell (`CVE-2021-44228`), then prints a structured JSON report.

`uv run python main.py` only prints a hello message — it is not the agent.
