from typing import Literal
from langchain.agents import create_agent
from langchain.agents.middleware import ModelCallLimitMiddleware, ToolRetryMiddleware, wrap_tool_call
from langchain.messages import ToolMessage
from pydantic import BaseModel, Field

from psc.config import MODEL
from psc.tools import list_manifests, lookup_cve, scan_k8s_manifest

class Finding(BaseModel):
    rule_or_cve: str = Field(description="Scanner rule ID (PSC-K8S-xxx) or CVE ID")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    resource: str = Field(description="Kubernetes resource or package affected")
    fix: str = Field(description="One-sentence remediation")

class TriageReport(BaseModel):
    """Structured result the agent must return."""
    overall_risk: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    findings: list[Finding]
    summary: str = Field(description="Two-sentence executive summary")

SYSTEM_PROMPT = """You are Platform Security Copilot, a DevSecOps triage assistant.
Use tools to gather facts; never guess CVE severity or scanner results.
Rank findings most severe first. overall_risk is the highest severity found, or NONE."""

@wrap_tool_call
def tool_guardrail(request, handler):
    """Turn unexpected tool exceptions into a message the model can act on."""
    try:
        return handler(request)
    except Exception as e:
        return ToolMessage(content=f"Tool '{request.tool_call['name']}' failed: {e}. Try another approach.",
                           tool_call_id=request.tool_call["id"], status="error")

def build_agent(model=MODEL, tools=None, **kwargs):
    return create_agent(
        model=model,
        tools=tools or [lookup_cve, scan_k8s_manifest, list_manifests],
        system_prompt=SYSTEM_PROMPT,
        response_format=TriageReport,
        middleware=[
            ModelCallLimitMiddleware(run_limit=15),
            ToolRetryMiddleware(max_retries=2, tools=["lookup_cve"]),
            tool_guardrail,
        ],
        **kwargs,
    )

agent = build_agent()

if __name__ == "__main__":
    result = agent.invoke({"messages": [{"role": "user", "content":
        "Triage payments-api.yaml. The image also bundles log4j-core 2.14 (CVE-2021-44228)."}]})
    print(result["structured_response"].model_dump_json(indent=2))