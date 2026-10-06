from dataclasses import dataclass
from typing import Literal, TypedDict

from langchain.chat_models import init_chat_model
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime
from langgraph.store.memory import InMemoryStore
from langgraph.types import Command, interrupt
from pydantic import BaseModel, Field

from psc.config import MODEL
from psc.rag import search_runbooks
from psc.spinner import Spinner
from psc.tools import MANIFEST_DIR, scan_k8s_manifest

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

class RemediationState(TypedDict, total=False):
    manifest: str
    findings: list[dict]
    suppressed: list[str]   # rules skipped due to a stored risk acceptance
    plan: dict
    decision: dict
    report: str

@dataclass
class Context:
    """Per-run configuration that is NOT state: who is asking, for which team."""
    team: str = "platform"
    reviewer: str = "unknown"

class RemediationPlan(BaseModel):
    steps: list[str] = Field(description="Ordered remediation steps, each citing a runbook section")
    patched_manifest: str = Field(description="The full corrected Kubernetes YAML")
    sla: str = Field(description="Deadline from the SLA runbook for the highest-severity finding")

def get_llm():
    # Claude Sonnet 5 rejects `temperature` ("deprecated for this model").
    return init_chat_model(MODEL)

def scan(state: RemediationState, runtime: Runtime[Context]) -> dict:
    """Deterministic step: no LLM needed to run a scanner."""
    result = scan_k8s_manifest.invoke({"manifest": state["manifest"]})
    findings = [f for r in result.get("resources", []) for f in r["findings"]]
    # Long-term memory: skip rules this team has formally accepted the risk for.
    accepted = {i.key for i in runtime.store.search(("risk_acceptances", runtime.context.team))}
    kept = [f for f in findings if f["rule"] not in accepted]
    return {"findings": kept, "suppressed": sorted(accepted & {f["rule"] for f in findings})}

def plan(state: RemediationState) -> dict:
    if not state["findings"]:
        return {"plan": {"steps": [], "patched_manifest": "", "sla": "n/a"}}
    rules = sorted({f["rule"] for f in state["findings"]})
    context = "\n\n".join(search_runbooks.invoke({"query": r}) for r in rules)
    context += "\n\n" + search_runbooks.invoke({"query": "remediation SLA by severity"})
    path = MANIFEST_DIR / state["manifest"]
    yaml_text = path.read_text() if path.exists() else state["manifest"]
    llm = get_llm().with_structured_output(RemediationPlan)
    result = llm.invoke(
        f"Write a remediation plan.\n\nFINDINGS:\n{state['findings']}\n\nMANIFEST:\n{yaml_text}\n\n"
        f"RUNBOOKS (cite these):\n{context}")
    return {"plan": result.model_dump()}

def route_after_plan(state: RemediationState) -> Literal["human_review", "finalize"]:
    worst = max((SEVERITY_RANK[f["severity"]] for f in state["findings"]), default=0)
    return "human_review" if worst >= SEVERITY_RANK["HIGH"] else "finalize"

def human_review(state: RemediationState, runtime: Runtime[Context]) -> Command:
    """Pause the graph. State is checkpointed; resume later from any process."""
    decision = interrupt({
        "question": "Approve this remediation plan?",
        "findings": state["findings"], "plan": state["plan"],
        "options": ["approve", "reject", "accept_risk"],
    })
    if decision["action"] == "accept_risk":
        for rule in decision.get("rules", []):   # long-term memory write
            runtime.store.put(("risk_acceptances", runtime.context.team), rule,
                              {"by": runtime.context.reviewer, "note": decision.get("note", "")})
    return Command(update={"decision": decision}, goto="finalize")

def finalize(state: RemediationState) -> dict:
    d = state.get("decision", {"action": "auto-approved (no HIGH/CRITICAL findings)"})
    lines = [f"# Remediation report: {state['manifest']}", f"Decision: {d['action']}"]
    if d.get("note"):
        lines.append(f"Reviewer note: {d['note']}")
    if state.get("suppressed"):
        lines.append(f"Suppressed by risk acceptance: {', '.join(state['suppressed'])}")
    lines += [f"- [{f['severity']}] {f['rule']}: {f['issue']}" for f in state["findings"]]
    if state["plan"].get("steps"):
        lines += ["", f"SLA: {state['plan']['sla']}", "Steps:"]
        lines += [f"{i}. {s}" for i, s in enumerate(state["plan"]["steps"], 1)]
    return {"report": "\n".join(lines)}

builder = StateGraph(RemediationState, context_schema=Context)
builder.add_node("scan", scan)
builder.add_node("plan", plan)
builder.add_node("human_review", human_review)
builder.add_node("finalize", finalize)
builder.add_edge(START, "scan")
builder.add_edge("scan", "plan")
builder.add_conditional_edges("plan", route_after_plan)
builder.add_edge("finalize", END)

# Agent Server injects its own Postgres checkpointer + store, so export a graph without them.
graph = builder.compile()

if __name__ == "__main__":
    app = builder.compile(checkpointer=InMemorySaver(), store=InMemoryStore())
    ctx = Context(team="payments", reviewer="adam")

    cfg = {"configurable": {"thread_id": "payments-api-1"}}
    with Spinner("Planning remediation"):
        out = app.invoke({"manifest": "payments-api.yaml"}, cfg, context=ctx)
    print("Paused with:", out["__interrupt__"][0].value["question"])
    print("Next node:", app.get_state(cfg).next)

    # Human accepts the risk on the mutable tag and approves the rest
    with Spinner("Applying review decision"):
        out = app.invoke(Command(resume={"action": "accept_risk", "rules": ["PSC-K8S-005"],
                                         "note": "Tag pinning lands with the Q4 registry migration"}), cfg, context=ctx)
    print(out["report"])

    # New thread, same team: long-term memory suppresses PSC-K8S-005
    cfg2 = {"configurable": {"thread_id": "payments-api-2"}}
    with Spinner("Planning remediation"):
        app.invoke({"manifest": "payments-api.yaml"}, cfg2, context=ctx)
    print("\nRun 2 suppressed:", app.get_state(cfg2).values["suppressed"])