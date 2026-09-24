from pathlib import Path
import httpx, yaml
from langchain.tools import tool

MANIFEST_DIR = Path(__file__).parent.parent / "data" / "manifests"

# Offline cache so the demo runs air-gapped; live NVD lookup is the fallback.
CVE_CACHE = {
    "CVE-2021-44228": {"name": "Log4Shell", "cvss": 10.0, "severity": "CRITICAL", "kev": True,
                       "summary": "Log4j2 JNDI lookup allows unauthenticated RCE.", "fixed_in": "log4j-core 2.17.1"},
    "CVE-2024-3094":  {"name": "xz backdoor", "cvss": 10.0, "severity": "CRITICAL", "kev": False,
                       "summary": "Backdoor in xz/liblzma 5.6.0-5.6.1 enables sshd auth bypass.", "fixed_in": "xz 5.6.2"},
    "CVE-2023-44487": {"name": "HTTP/2 Rapid Reset", "cvss": 7.5, "severity": "HIGH", "kev": True,
                       "summary": "HTTP/2 stream cancellation enables DoS.", "fixed_in": "vendor-specific"},
    "CVE-2024-21626": {"name": "Leaky Vessels (runc)", "cvss": 8.6, "severity": "HIGH", "kev": False,
                       "summary": "runc fd leak allows container escape.", "fixed_in": "runc 1.1.12"},
}

@tool
def lookup_cve(cve_id: str) -> dict:
    """Look up a CVE by ID (e.g. CVE-2021-44228). Returns severity, CVSS score, CISA KEV status and fix version."""
    cve_id = cve_id.strip().upper()
    if cve_id in CVE_CACHE:
        return {"id": cve_id, "source": "cache", **CVE_CACHE[cve_id]}
    try:
        r = httpx.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve_id}, timeout=10)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return {"id": cve_id, "error": "CVE not found. Check the format: CVE-YYYY-NNNNN."}
        cve = vulns[0]["cve"]
        m = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        return {"id": cve_id, "source": "nvd", "cvss": m.get("baseScore"),
                "severity": m.get("baseSeverity", "UNKNOWN"), "summary": cve["descriptions"][0]["value"][:500]}
    except httpx.HTTPError as e:
        return {"id": cve_id, "error": f"NVD lookup failed ({type(e).__name__}). Treat severity as UNKNOWN."}

def _scan(doc: dict) -> list[dict]:
    findings = []
    spec = doc.get("spec", {}).get("template", {}).get("spec", doc.get("spec", {}))
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(flag):
            findings.append({"rule": "PSC-K8S-004", "severity": "HIGH", "container": "*", "issue": f"{flag}: true"})
    for c in spec.get("containers", []):
        sc, name, image = c.get("securityContext") or {}, c.get("name", "?"), c.get("image", "")
        if sc.get("privileged"):
            findings.append({"rule": "PSC-K8S-001", "severity": "CRITICAL", "container": name, "issue": "privileged container"})
        if not sc.get("runAsNonRoot"):
            findings.append({"rule": "PSC-K8S-002", "severity": "MEDIUM", "container": name, "issue": "may run as root"})
        if sc.get("allowPrivilegeEscalation", True):
            findings.append({"rule": "PSC-K8S-003", "severity": "MEDIUM", "container": name, "issue": "privilege escalation allowed"})
        if "@sha256:" not in image and (image.endswith(":latest") or ":" not in image.split("/")[-1]):
            findings.append({"rule": "PSC-K8S-005", "severity": "MEDIUM", "container": name, "issue": f"mutable tag: {image}"})
        if not (c.get("resources") or {}).get("limits"):
            findings.append({"rule": "PSC-K8S-006", "severity": "LOW", "container": name, "issue": "no resource limits"})
    return findings

@tool
def scan_k8s_manifest(manifest: str) -> dict:
    """Scan Kubernetes YAML for security misconfigurations.

    Args:
        manifest: Raw YAML text, OR a file name in data/manifests (e.g. 'payments-api.yaml').
    """
    if manifest.strip().endswith((".yaml", ".yml")) and "\n" not in manifest:
        path = MANIFEST_DIR / manifest.strip()
        if not path.exists():
            return {"error": f"No manifest named {manifest}. Available: {[p.name for p in MANIFEST_DIR.glob('*.yaml')]}"}
        manifest = path.read_text()
    try:
        docs = [d for d in yaml.safe_load_all(manifest) if d]
    except yaml.YAMLError as e:
        return {"error": f"Invalid YAML: {e}"}
    return {"resources": [{"kind": d.get("kind"), "name": d.get("metadata", {}).get("name"),
                           "findings": _scan(d)} for d in docs]}

@tool
def list_manifests() -> list[str]:
    """List the Kubernetes manifest files available to scan."""
    return sorted(p.name for p in MANIFEST_DIR.glob("*.yaml"))