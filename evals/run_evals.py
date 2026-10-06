from langchain.agents import create_agent
from langsmith import Client
from openevals.llm import create_llm_as_judge
from openevals.prompts import CORRECTNESS_PROMPT

from psc import m1_triage_agent as m1
from psc.config import FAST_MODEL

client = Client()
DATASET = "psc-triage-v1"

# 1. Dataset: inputs + reference outputs
EXAMPLES = [
    {"inputs": {"question": "Triage payments-api.yaml."},
     "outputs": {"overall_risk": "CRITICAL", "must_find": ["PSC-K8S-001", "PSC-K8S-004", "PSC-K8S-005"],
                 "answer": "Critical: privileged container; High: hostNetwork; plus root, escalation, :latest tag, no limits."}},
    {"inputs": {"question": "Triage web-frontend.yaml."},
     "outputs": {"overall_risk": "NONE", "must_find": [],
                 "answer": "No findings: the deployment is hardened and pinned by digest."}},
    {"inputs": {"question": "We run log4j-core 2.14 in the billing service. How bad is it and what's the SLA?"},
     "outputs": {"overall_risk": "CRITICAL", "must_find": ["CVE-2021-44228"],
                 "answer": "Log4Shell, CVSS 10, in CISA KEV: patch to 2.17.1+ within 24 hours."}},
    {"inputs": {"question": "Is CVE-2023-44487 a concern for our nginx ingress?"},
     "outputs": {"overall_risk": "HIGH", "must_find": ["CVE-2023-44487"],
                 "answer": "HTTP/2 Rapid Reset, HIGH (7.5), in KEV; upgrade nginx to 1.25.3+, 24h deadline per KEV."}},
    {"inputs": {"question": "Triage this: apiVersion: v1\nkind: Pod\nmetadata: {name: debug}\nspec:\n  hostPID: true\n  containers:\n  - {name: sh, image: busybox}"},
     "outputs": {"overall_risk": "HIGH", "must_find": ["PSC-K8S-004", "PSC-K8S-005"],
                 "answer": "hostPID breaks isolation (HIGH); busybox is untagged; runs as root; no limits."}},
]

def ensure_dataset():
    if client.has_dataset(dataset_name=DATASET):
        return
    ds = client.create_dataset(DATASET, description="PSC triage golden set")
    client.create_examples(dataset_id=ds.id, examples=EXAMPLES)

# 2. Evaluators: deterministic first, LLM-as-judge for the fuzzy part
def risk_matches(outputs: dict, reference_outputs: dict) -> bool:
    return outputs["overall_risk"] == reference_outputs["overall_risk"]

def finding_recall(outputs: dict, reference_outputs: dict) -> float:
    expected = set(reference_outputs["must_find"])
    if not expected:  # clean manifest: reward reporting nothing
        return 1.0 if not outputs["findings"] else 0.0
    found = {f["rule_or_cve"] for f in outputs["findings"]}
    return len(expected & found) / len(expected)

_judge = create_llm_as_judge(prompt=CORRECTNESS_PROMPT, model=FAST_MODEL, feedback_key="correctness")

def correctness(inputs: dict, outputs: dict, reference_outputs: dict):
    return _judge(inputs=inputs["question"], outputs=outputs["summary"],
                  reference_outputs=reference_outputs["answer"])

# 3. Two prompt variants to A/B
PROMPTS = {
    "v1-baseline": m1.SYSTEM_PROMPT,
    "v2-sla-first": m1.SYSTEM_PROMPT + (
        "\nAlways check CISA KEV status. In the summary, lead with the single most urgent action and its "
        "deadline. If a scan returns no findings, overall_risk is NONE and findings is empty."),
}

def make_target(system_prompt: str):
    agent = create_agent(
        model=m1.MODEL, tools=[m1.lookup_cve, m1.scan_k8s_manifest, m1.list_manifests, m1.search_runbooks],
        system_prompt=system_prompt, response_format=m1.TriageReport)

    def target(inputs: dict) -> dict:
        result = agent.invoke({"messages": [{"role": "user", "content": inputs["question"]}]})
        return result["structured_response"].model_dump()
    return target

if __name__ == "__main__":
    ensure_dataset()
    for variant, prompt in PROMPTS.items():
        client.evaluate(
            make_target(prompt),
            data=DATASET,
            evaluators=[risk_matches, finding_recall, correctness],
            experiment_prefix=f"triage-{variant}",
            metadata={"prompt_variant": variant, "model": m1.MODEL},
            max_concurrency=4,
            num_repetitions=2,  # LLMs are non-deterministic: repeat to separate signal from noise
        )