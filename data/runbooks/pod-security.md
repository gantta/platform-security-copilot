# Pod Security

Non-system namespaces enforce Pod Security Admission `restricted`. `scan_k8s_manifest` raises the rules below. Ship every change as a pull request to the GitOps repo and let Argo CD reconcile it. Do not run `kubectl apply` against the cluster.

## Remediation SLA

Deadline is the SLA of the highest-severity open finding on the workload.

| Severity | Deadline | Rules |
| --- | --- | --- |
| CRITICAL | 24 hours | PSC-K8S-001 |
| HIGH | 7 days | PSC-K8S-004 |
| MEDIUM | 30 days | PSC-K8S-002, PSC-K8S-003 |
| LOW | 90 days | other workload findings |

CISA KEV findings are emergency and use the 24-hour deadline even when CVSS would land lower. Re-scan the manifest after the GitOps merge; the finding stays open until the scanner no longer reports that rule.

## PSC-K8S-001 Privileged containers

**Severity:** CRITICAL. **SLA:** 24 hours.

**Detect:** `securityContext.privileged: true` on a container. The scanner reports `privileged container`.

A privileged container shares the node's device access and can load kernel modules, which removes the isolation the node depends on. The restricted profile rejects this field.

**Fix:** Delete `privileged: true` from the container `securityContext`. Removing the field is the compliant state. If the process needs one Linux capability, add only that capability and drop every other one. Most services need none.

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
```

Open a GitOps pull request, then re-scan. PSC-K8S-001 is clear only when `privileged` is absent.

## PSC-K8S-002 Run as non-root

**Severity:** MEDIUM. **SLA:** 30 days.

**Detect:** container `securityContext.runAsNonRoot` is missing or not `true`. The scanner reports `may run as root`.

Without this field the container starts as uid 0 when the image has no `USER`, or when `USER` is root. A compromised process then has root inside the container.

**Fix:** Set both fields on the container `securityContext`. Pod-level is acceptable when every container in the pod uses the same uid.

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
```

`10001` is the platform default unprivileged uid. If the image already declares a non-root `USER`, set `runAsUser` to that uid instead. The process must be able to write its logs, caches, and mounted volumes as that uid. Move any listen port below 1024 to a higher port rather than running as root.

## PSC-K8S-003 Block privilege escalation

**Severity:** MEDIUM. **SLA:** 30 days.

**Detect:** `allowPrivilegeEscalation` is omitted or `true`. Kubernetes treats an omitted field as allowed, so a missing key is still a finding. The scanner reports `privilege escalation allowed`.

When escalation is allowed, a process can gain more privileges than its parent through file capabilities or setuid binaries. The restricted profile requires this field to be false.

**Fix:** Set the field explicitly and drop all capabilities.

```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

The finding clears only when the field is explicitly `false`. Apply the change through GitOps and re-scan.

## PSC-K8S-004 Host namespaces

**Severity:** HIGH. **SLA:** 7 days.

**Detect:** pod spec `hostNetwork`, `hostPID`, or `hostIPC` set to `true`. The scanner reports the flag, for example `hostNetwork: true`. The container column is `*` because the setting is on the pod, not one container.

- `hostNetwork` shares the node network stack, so the pod can bind host ports and bypass NetworkPolicy.
- `hostPID` shares the node process table, so the container can see and signal host processes.
- `hostIPC` shares host inter-process memory.

**Fix:** Delete `hostNetwork`, `hostPID`, and `hostIPC` from `spec.template.spec` (or `spec` on a Pod). Absence is the compliant state. Reach other workloads through a Service, not the host network. A pod that needs the host process table does not belong in a non-system namespace; debug with an ephemeral container in the target pod instead.

```yaml
spec:
  template:
    spec:
      containers:
        - name: api
```

Re-scan after the GitOps merge. The rule is clear when none of the three flags are true.
