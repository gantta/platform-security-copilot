---
name: k8s-hardening
description: Produce a hardened, patched version of a Kubernetes manifest. Use when asked to fix, patch or harden a manifest.
---

# k8s-hardening

## Instructions
1. Scan the manifest with `scan_k8s_manifest` first.
2. For each finding, apply the matching fix:
   - PSC-K8S-001: delete `privileged: true`
   - PSC-K8S-002: add `runAsNonRoot: true` and `runAsUser: 10001`
   - PSC-K8S-003: add `allowPrivilegeEscalation: false`
   - PSC-K8S-004: delete `hostNetwork`/`hostPID`/`hostIPC`
   - PSC-K8S-005: replace the tag with `@sha256:<digest>` and leave a TODO for the real digest
   - PSC-K8S-006: add requests/limits (default 100m/128Mi requests, 500m/256Mi limits)
3. Write the patched file to `/patches/<name>.yaml` and re-scan it; the re-scan must return no findings except PSC-K8S-005 TODOs.