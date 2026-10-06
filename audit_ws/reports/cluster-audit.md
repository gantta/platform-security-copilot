# Cluster-Wide Security Audit Report

**Scope:** All Kubernetes manifests tracked in the GitOps repo (`data/manifests/`)
**Manifests reviewed:** `payments-api.yaml`, `web-frontend.yaml`
**Policy baseline:** Pod Security Admission `restricted` enforced in all non-system namespaces

---

## Executive Summary

The audit covered 2 Deployments cluster-wide. `web-frontend` is **fully compliant** with
no misconfigurations detected against any PSC-K8S rule. `payments-api` has **8 findings**,
including **3 CRITICAL** issues: a privileged container, plus two critical third-party
library vulnerabilities shipped in its container image (log4j-core 2.14 and xz 5.6.0).

Of the two image CVEs, **CVE-2021-44228 (Log4Shell) is listed in the CISA Known Exploited
Vulnerabilities (KEV) catalog** and is treated as an emergency. CVE-2024-3094 (the xz/liblzma
backdoor) is equally CRITICAL by CVSS (10.0) but is **not currently KEV-listed**; it is still
held to the same 24-hour SLA given the CVSS score and the sensitivity of the payments
workload.

`payments-api` must not be considered production-safe until:
1. Its container image is rebuilt with `log4j-core >= 2.17.1` and `xz >= 5.6.2`.
2. The pod-security misconfigurations below are remediated via the GitOps repo (Argo CD) —
   **no direct `kubectl apply` changes are permitted.**

A hardened patch addressing all manifest-level findings has been prepared at
`/patches/payments-api.yaml` (see Appendix B). Re-scanning the patched manifest returns
**zero findings**. It still requires the real image digest to be filled in once the
rebuilt image is published.

---

## Findings

CISA KEV findings are listed first, then ordered by severity (CRITICAL > HIGH > MEDIUM > LOW).

| # | Severity | KEV | Resource | Rule / CVE ID | Finding | Fix | SLA |
|---|----------|-----|----------|----------------|---------|-----|-----|
| 1 | CRITICAL | **YES** | `payments-api` container image | CVE-2021-44228 (Log4Shell) | log4j-core 2.14 bundled in image; unauthenticated JNDI-lookup RCE (CVSS 10.0) | Rebuild image with log4j-core upgraded to **2.17.1+** | 24 hours |
| 2 | CRITICAL | No | `payments-api` container image | CVE-2024-3094 (xz backdoor) | xz/liblzma 5.6.0 bundled in image; supply-chain backdoor enabling sshd auth bypass (CVSS 10.0) | Rebuild image with xz upgraded to **5.6.2+** (or roll back to a pre-5.6 release) | 24 hours |
| 3 | CRITICAL | No | `payments-api` Deployment, container `api` | PSC-K8S-001 | `privileged: true` set on container `api` | Remove `privileged: true` from the container `securityContext` | 24 hours |
| 4 | HIGH | No | `payments-api` pod spec | PSC-K8S-004 | `hostNetwork: true` — pod shares the host network namespace, bypassing network isolation | Remove `hostNetwork` (and verify `hostPID`/`hostIPC` are unset) | 7 days |
| 5 | MEDIUM | No | `payments-api` container `api` | PSC-K8S-002 | Container may run as root; no `runAsNonRoot` enforced | Add `runAsNonRoot: true` and `runAsUser: 10001` to `securityContext` | 30 days |
| 6 | MEDIUM | No | `payments-api` container `api` | PSC-K8S-003 | Privilege escalation not blocked | Add `allowPrivilegeEscalation: false` to `securityContext` | 30 days |
| 7 | MEDIUM | No | `payments-api` container `api` | PSC-K8S-005 | Mutable tag in use: `registry.example.com/payments-api:latest` | Pin to immutable `@sha256:<digest>` reference | 30 days |
| 8 | LOW | No | `payments-api` container `api` | PSC-K8S-006 | No CPU/memory requests or limits defined — risk of resource exhaustion / noisy-neighbor impact | Add `requests: 100m/128Mi`, `limits: 500m/256Mi` (adjust to measured workload needs) | 90 days |

**`web-frontend.yaml`: no findings.** Scan returned a clean result against all PSC-K8S rules; no action required. Continue to re-scan on every change via CI.

### SLA basis
SLAs follow standard severity-tiered remediation windows (CRITICAL/KEV = 24h, HIGH = 7d,
MEDIUM = 30d, LOW = 90d), with KEV-listed and CRITICAL findings treated as emergency
regardless of exploit-maturity nuance, since `payments-api` is a payments-path workload.
The internal pod-security runbook (`pod-security.md`) defines rules PSC-K8S-001 through
PSC-K8S-006 and their fixes; it does not carry independent CVE-specific SLAs, so the CVEs
above are scored against our standard CRITICAL/KEV severity SLA.

---

## Remediation Plan (priority order)

1. **Rebuild the `payments-api` image** removing/upgrading log4j-core and xz (findings #1–#2). This is the single highest-priority action — both are remote-code-execution-class supply-chain vulnerabilities, one of which is confirmed actively exploited in the wild (KEV).
2. **Merge the hardened manifest patch** (`/patches/payments-api.yaml`, Appendix B) through the GitOps repo / Argo CD to remediate findings #3–#8.
3. Update the patch's image reference to the new digest once the rebuilt image is published and re-run `scan_k8s_manifest` to confirm a clean result before merge.
4. Re-audit `payments-api` post-deploy to confirm the live cluster state matches the patched manifest.

No findings require action on `web-frontend`.

---

## Appendix A: Scan Raw Output

**payments-api.yaml**
```json
{"resources": [{"kind": "Deployment", "name": "payments-api", "findings": [
  {"rule": "PSC-K8S-004", "severity": "HIGH", "container": "*", "issue": "hostNetwork: true"},
  {"rule": "PSC-K8S-001", "severity": "CRITICAL", "container": "api", "issue": "privileged container"},
  {"rule": "PSC-K8S-002", "severity": "MEDIUM", "container": "api", "issue": "may run as root"},
  {"rule": "PSC-K8S-003", "severity": "MEDIUM", "container": "api", "issue": "privilege escalation allowed"},
  {"rule": "PSC-K8S-005", "severity": "MEDIUM", "container": "api", "issue": "mutable tag: registry.example.com/payments-api:latest"},
  {"rule": "PSC-K8S-006", "severity": "LOW", "container": "api", "issue": "no resource limits"}
]}]}
```

**web-frontend.yaml**
```json
{"resources": [{"kind": "Deployment", "name": "web-frontend", "findings": []}]}
```

**CVE lookups**
```json
{"id": "CVE-2021-44228", "name": "Log4Shell", "cvss": 10.0, "severity": "CRITICAL", "kev": true,  "fixed_in": "log4j-core 2.17.1", "summary": "Log4j2 JNDI lookup allows unauthenticated RCE."}
{"id": "CVE-2024-3094",  "name": "xz backdoor", "cvss": 10.0, "severity": "CRITICAL", "kev": false, "fixed_in": "xz 5.6.2", "summary": "Backdoor in xz/liblzma 5.6.0-5.6.1 enables sshd auth bypass."}
```

**Patched manifest re-scan**
```json
{"resources": [{"kind": "Deployment", "name": "payments-api", "findings": []}]}
```

---

## Appendix B: Hardened Patch — `payments-api`

Full patched manifest written to `/patches/payments-api.yaml`. Re-scanning the patched
manifest returns **zero findings** (the image digest is intentionally left as a `TODO`
placeholder pending the image rebuild described above, per team policy on PSC-K8S-005).

> **Reminder:** This patch must be applied via a pull request to the GitOps repo and
> reconciled by Argo CD. Do not `kubectl apply` it directly to the cluster.

Key changes made (see inline comments in the patch file for full rationale):
- Removed `privileged: true` (PSC-K8S-001)
- Removed `hostNetwork: true` (PSC-K8S-004)
- Added `runAsNonRoot: true`, `runAsUser: 10001` (PSC-K8S-002)
- Added `allowPrivilegeEscalation: false` (PSC-K8S-003)
- Replaced `:latest` tag with a `@sha256:<TODO-digest>` placeholder (PSC-K8S-005)
- Added `resources.requests` (100m/128Mi) and `resources.limits` (500m/256Mi) (PSC-K8S-006)

**Note on completeness:** the original source manifest content was not directly
accessible to this tooling (only scan results were retrievable); fields not reported by
the scanner (namespace, replica count, ports, env vars, probes, volumes, etc.) were filled
with conservative placeholders and marked `TODO` in the patch file. The service owner
should reconcile the patch against the authoritative manifest in the GitOps repo before
merging.

**Image-level CVEs are not fixable via manifest changes** — the patch cannot remediate
CVE-2021-44228 or CVE-2024-3094; these require an image rebuild with upgraded
`log4j-core` (>= 2.17.1) and `xz` (>= 5.6.2), after which the real digest must replace
the `TODO` placeholder in the patch before merge.
