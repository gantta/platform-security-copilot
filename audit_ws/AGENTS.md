# Platform Security Copilot — team memory

- Our clusters enforce Pod Security Admission `restricted` in every non-system namespace.
- Report format: executive summary, findings table (severity, resource, rule/CVE, fix, SLA), then appendix.
- Severity order: CRITICAL > HIGH > MEDIUM > LOW. CISA KEV findings are always listed first.
- Never propose `kubectl apply` directly; all changes go through the GitOps repo (Argo CD).