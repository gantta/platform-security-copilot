import sys

from langchain.agents import create_agent
from langchain.tools import tool
from langgraph.checkpoint.memory import InMemorySaver

from psc.config import FAST_MODEL, MODEL
from psc.rag import search_runbooks
from psc.spinner import Spinner
from psc.tools import list_manifests, lookup_cve, scan_k8s_manifest

FINAL_ANSWER_RULE = ("Your final message is the ONLY thing the supervisor sees. "
                     "Put every fact, ID and severity in it as a concise bullet list.")

# Specialists: narrow tools + narrow prompt. Cheap model where the task is mechanical.
vuln_analyst = create_agent(
    FAST_MODEL, tools=[lookup_cve], name="vuln_analyst",
    system_prompt=f"You assess CVEs: severity, CVSS, CISA KEV status, fixed version. {FINAL_ANSWER_RULE}")

k8s_auditor = create_agent(
    FAST_MODEL, tools=[scan_k8s_manifest, list_manifests], name="k8s_auditor",
    system_prompt=f"You audit Kubernetes manifests with the scanner. Report every finding. {FINAL_ANSWER_RULE}")

remediation_writer = create_agent(
    MODEL, tools=[search_runbooks], name="remediation_writer",
    system_prompt=("You write remediation steps grounded ONLY in the runbooks. Cite 'file > section' for each "
                   f"step and state the SLA. If the runbooks don't cover something, say so. {FINAL_ANSWER_RULE}"))

def _ask(agent, task: str) -> str:
    """Subagents are stateless: they get only the task and return only their final message."""
    result = agent.invoke({"messages": [{"role": "user", "content": task}]})
    return result["messages"][-1].content

@tool
def ask_vuln_analyst(task: str) -> str:
    """Delegate CVE research. Include every CVE ID in the task."""
    return _ask(vuln_analyst, task)

@tool
def ask_k8s_auditor(task: str) -> str:
    """Delegate a Kubernetes manifest audit. Name the manifest file(s) in the task."""
    return _ask(k8s_auditor, task)

@tool
def ask_remediation_writer(task: str) -> str:
    """Delegate writing remediation steps. Include the exact findings (rule IDs / CVEs + severities)."""
    return _ask(remediation_writer, task)

def build_supervisor(checkpointer=None):
    return create_agent(
        MODEL,
        tools=[ask_vuln_analyst, ask_k8s_auditor, ask_remediation_writer],
        name="psc_supervisor",
        system_prompt=("You lead a security review team. Plan, delegate to specialists (in parallel when "
                       "independent), then synthesize ONE prioritized answer with severities, fixes and SLAs. "
                       "Never invent findings the specialists did not report."),
        checkpointer=checkpointer,
    )

# Agent Server supplies persistence and refuses graphs that bring their own checkpointer,
# so the exported graph has none. Local runs add InMemorySaver below.
supervisor = build_supervisor()

def _print_update(step: dict) -> None:
    for node, update in step.items():
        for m in update.get("messages", []):
            calls = [c["name"] for c in getattr(m, "tool_calls", [])]
            print(f"[{node}] {'-> ' + ', '.join(calls) if calls else str(m.content)[:300]}")

def _next_step(steps):
    """Wait for the next stream update, showing a spinner on a terminal."""
    if not sys.stderr.isatty():
        return next(steps, None)
    with Spinner("Review in progress"):
        return next(steps, None)

if __name__ == "__main__":
    supervisor = build_supervisor(InMemorySaver())  # local multi-turn memory
    cfg = {"configurable": {"thread_id": "review-1"}}
    q = "Review payments-api.yaml. Its image also ships xz 5.6.0 (CVE-2024-3094). What do we fix first?"
    steps = supervisor.stream({"messages": [{"role": "user", "content": q}]}, cfg, stream_mode="updates")
    if not sys.stderr.isatty():
        print("Review in progress...", file=sys.stderr)
    while True:
        step = _next_step(steps)
        if step is None:
            break
        _print_update(step)
    # Follow-up on the same thread: the supervisor remembers the review.
    with Spinner("Drafting ticket title"):
        r = supervisor.invoke({"messages": [{"role": "user", "content": "Draft the Jira ticket title for item 1."}]}, cfg)
    print(r["messages"][-1].content)