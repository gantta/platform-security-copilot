import sys
from pathlib import Path

from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langgraph.checkpoint.memory import InMemorySaver

from psc.config import FAST_MODEL, MODEL
from psc.rag import search_runbooks
from psc.spinner import Spinner
from psc.tools import list_manifests, lookup_cve, scan_k8s_manifest

WORKSPACE = Path(__file__).parent.parent / "audit_ws"

subagents = [
    {
        "name": "cve-researcher",
        "description": "Researches one or more CVEs in depth: severity, KEV status, fix version, compensating controls.",
        "system_prompt": "Research the CVEs you are given with lookup_cve and search_runbooks. Return a compact table.",
        "tools": [lookup_cve, search_runbooks],
        "model": FAST_MODEL,
    },
    {
        "name": "manifest-auditor",
        "description": "Audits ONE Kubernetes manifest and returns its findings with runbook-cited fixes.",
        "system_prompt": ("Scan the manifest you are given, look up the fix for each rule in the runbooks, "
                          "and return findings as a markdown table: severity | rule | issue | fix | SLA."),
        "tools": [scan_k8s_manifest, search_runbooks],
        "model": FAST_MODEL,
    },
]

def build_audit_agent(checkpointer=None):
    return create_deep_agent(
        model=MODEL,
        tools=[list_manifests, scan_k8s_manifest, lookup_cve, search_runbooks],
        system_prompt=("You are a principal security engineer running a cluster-wide audit. Plan with write_todos, "
                       "delegate one manifest per manifest-auditor call, and write the final report to "
                       "/reports/cluster-audit.md following the report format in your memory."),
        subagents=subagents,
        # Real disk, sandboxed to the workspace: virtual_mode blocks '..', '~' and absolute-path escapes.
        backend=FilesystemBackend(root_dir=WORKSPACE, virtual_mode=True),
        memory=["/AGENTS.md"],             # always loaded
        skills=["/skills/"],               # loaded on demand
        interrupt_on={"edit_file": True},  # human approves edits to existing files
        checkpointer=checkpointer,         # interrupts need one: InMemorySaver locally, Postgres on Agent Server
    )

agent = build_audit_agent()  # exported for Agent Server (Module 7)

def _print_update(step: dict) -> None:
    for node, update in step.items():
        if not update:
            continue
        if "todos" in update:
            print("TODOS:", [f"{t['status']}: {t['content']}" for t in update["todos"]])
        for m in update.get("messages", []) if isinstance(update, dict) else []:
            for c in getattr(m, "tool_calls", []):
                print(f"[{node}] -> {c['name']}({str(c['args'])[:80]})")

def _next_step(steps):
    """Wait for the next stream update, showing a spinner on a terminal."""
    if not sys.stderr.isatty():
        return next(steps, None)
    with Spinner("Audit in progress"):
        return next(steps, None)

if __name__ == "__main__":
    agent = build_audit_agent(InMemorySaver())
    cfg = {"configurable": {"thread_id": "audit-1"}}
    task = ("Audit every manifest in the cluster. The payments image also ships log4j-core 2.14 "
            "(CVE-2021-44228) and xz 5.6.0 (CVE-2024-3094). Then produce a hardened patch for payments-api.")
    steps = agent.stream({"messages": [{"role": "user", "content": task}]}, cfg, stream_mode="updates")
    if not sys.stderr.isatty():
        print("Audit in progress...", file=sys.stderr)
    while True:
        step = _next_step(steps)
        if step is None:
            break
        _print_update(step)
    print("\nFiles written:", sorted(str(p.relative_to(WORKSPACE)) for p in WORKSPACE.rglob("*") if p.is_file()))