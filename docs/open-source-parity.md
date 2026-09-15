# Open-source readiness scanner parity

Canonical's readiness system intentionally does **not** try to reimplement every cloud-security, compliance, Kubernetes, IaC, and FinOps rule in one codebase. The native scanner supplies the stable, strict-read-only customer-account contract and a normalized finding model. Mature open-source scanners run behind fixed adapters as independent evidence sources.

This gives an engagement two useful properties:

1. Canonical can always run a small, understandable baseline whose network and command surface is auditable.
2. Canonical can cross-check that baseline against thousands of community-maintained rules without giving an MCP client arbitrary command execution.

## Architecture

```text
MCP client
   |
   +-- readiness_catalog ---------------------- offline provider matrix
   +-- account_readiness ---------------------- Canonical native collector
   +-- operational_readiness ------------------ fixed Prometheus + OpenCost GETs
   +-- browser_readiness ---------------------- GET/HEAD/OPTIONS-only console fallback
   |
   +-- external_tool_catalog ------------------ offline OSS capability matrix
   +-- external_tool_status ------------------- fixed local version probes
   +-- external_readiness --------------------- fixed OSS adapters
              |
              +-- Prowler
              +-- ScoutSuite
              +-- Trivy
              +-- Checkov
              +-- Kubescape
              +-- kube-bench
              +-- kubeaudit
              +-- Infracost
              +-- Powerpipe / Steampipe
```

There is no `exec`, `shell`, `command`, generic argument array, arbitrary URL, or arbitrary HTTP method exposed through MCP.

## Parity matrix

| Layer | Tool | What it adds | Customer-account access | Canonical adapter |
| --- | --- | --- | --- | --- |
| Native | Canonical `account_readiness` | Inventory, security baseline, backups, utilization evidence, spend/budget signals, provider-specific advice | Strict GET/fixed read CLI only | Built in |
| Runtime telemetry | Prometheus | Actual CPU, filesystem free space, memory, exporter/target health | Operator-configured read endpoint | Fixed GET PromQL |
| Kubernetes FinOps | OpenCost | Namespace allocation and budget evidence | Operator-configured read endpoint | Fixed GET allocation query |
| Cloud security/compliance | Prowler | Large multi-cloud security and compliance rule catalog | Provider credentials; **must be read-only** | Fixed provider + JSON-OCSF output |
| Independent cloud cross-check | ScoutSuite | Independent point-in-time attack-surface/configuration assessment | Provider credentials; **must be read-only** | Fixed provider, no browser, isolated report dir |
| IaC misconfiguration | Trivy | Terraform/CloudFormation/Kubernetes/Helm/Dockerfile configuration checks | None for local config scan | `trivy config --format json` only |
| IaC policy/graph | Checkov | Broad policy-as-code and graph checks for IaC and CI configuration | None for local config scan | Directory scan + JSON only |
| Kubernetes frameworks | Kubescape | NSA/CISA/CIS-style Kubernetes configuration and framework controls | Read-only kubeconfig for cluster mode | `scan` + JSON v2 only |
| Kubernetes CIS | kube-bench | CIS Kubernetes benchmark | Local/node and cluster reads | `--json` only |
| Kubernetes workload hardening | kubeaudit | Pod/workload security best-practice checks | Read-only kubeconfig for cluster mode | `all` + JSON only |
| FinOps / shift-left cost | Infracost | Pre-deploy monthly cost estimates from IaC | None for normal IaC pricing | `breakdown --format json` only |
| Benchmark-as-code | Powerpipe + Steampipe | Query-backed compliance/control packs across installed Steampipe connections | Connections **must be read-only** | Fixed benchmark id + JSON only |

### Useful adjacent tools not executed by the current adapter

**CloudQuery** is valuable for copying provider inventory into a normalized analytical store. Its normal `sync` workflow necessarily writes to a destination database/object store, so it is not yet invoked from `external_readiness`. We can consume a pre-populated CloudQuery database later without weakening the "no customer mutation" rule.

**OpenCost** is integrated separately through `operational_readiness`, not as a child process. Its API is read-only for Canonical's fixed allocation query and complements Infracost's pre-deploy estimate.

## Compliance parity

Prowler's current open-source compliance catalog spans CIS benchmarks, NIST SP 800-53/800-171/CSF, CISA guidance, FedRAMP, PCI DSS, ISO/IEC 27001, SOC 2, GDPR, HIPAA, MITRE ATT&CK, AWS Well-Architected/FTR, NIS2 and additional frameworks. The exact framework keys vary by provider and Prowler release, so Canonical should discover the installed catalog from the pinned Prowler binary rather than hard-code marketing-era framework names.

For readiness reporting, Canonical must distinguish:

- **machine-observable pass/fail** from a provider/tool check;
- **manual evidence** such as policies, training, contracts, incident exercises, access reviews, and management approvals;
- **unknown/unavailable** because permissions or telemetry are missing;
- **not applicable**, with a documented scope rationale.

A Prowler/Powerpipe benchmark is evidence collection, not certification. Canonical should map external check IDs to its own framework/control evidence graph while preserving tool/version provenance.

Recommended framework priorities for the Canonical product are:

1. CIS cloud/Kubernetes benchmarks.
2. NIST CSF + NIST SP 800-53.
3. SOC 2 trust-services readiness.
4. ISO/IEC 27001 readiness.
5. PCI DSS where cardholder-data scope exists.
6. HIPAA where protected-health-information scope exists.
7. GDPR/NIS2 where the customer's legal/geographic scope requires them.
8. Provider-native well-architected/security-framework checks.

The control engine should allow multiple frameworks to point to one evidence record rather than re-running the same expensive provider query for every framework.

## Fail-closed external execution

External scanners are powerful binaries, so Canonical wraps them more narrowly than a normal shell invocation:

- executable name is compiled into the adapter;
- allowed arguments are constructed by Canonical, not supplied by the MCP caller;
- no shell is used;
- provider values are enums, not arbitrary strings;
- local targets are canonicalized and must stay below `CANONICAL_AUDIT_ROOT`;
- the Powerpipe benchmark id accepts only ASCII letters, digits, `_`, `-`, and `.`;
- each process has a timeout;
- stdout/stderr and generated reports are bounded before parsing/returning;
- normalized MCP output is capped to 100 findings; the native scanner report can retain a reference/count for larger result sets;
- generated temporary reports are isolated and removed after parsing;
- tokens are inherited from the environment and never accepted as MCP parameters or printed into command arguments.

`CANONICAL_EXTERNAL_TOOL_TIMEOUT_SECS` controls the per-tool timeout and is clamped to 10–600 seconds. The default is 180 seconds.

`CANONICAL_AUDIT_ROOT` controls the only local filesystem tree external IaC/manifest scanners may inspect. It defaults to the current directory. In production engagements, point it at a dedicated read-only checkout or copied evidence directory rather than `/` or a developer home directory.

## Credential contract

Installing an external scanner does not make its upstream credential read-only. The account identity must independently be restricted at the provider.

Canonical should prefer:

- AWS audit roles such as SecurityAudit plus narrowly scoped monitoring/cost reads;
- GCP Viewer/Monitoring Viewer/Cloud Asset Viewer/Billing Viewer/Recommender Viewer as needed;
- Azure Reader/Monitoring Reader/Cost Management Reader;
- GitHub Apps or fine-grained tokens with read permissions only;
- Cloudflare API tokens containing only required `Read` groups;
- Kubernetes RBAC limited to `get`, `list`, and `watch` for cluster scanners.

If an external tool needs a permission outside the approved engagement read set, that evidence family should be marked unavailable instead of broadening the customer credential automatically.

## Recommended scan compositions

### AWS

Run:

1. `account_readiness(provider=aws)` for the Canonical baseline and spend/utilization evidence.
2. `external_readiness(tool=prowler, provider=aws)` for broad security/compliance coverage.
3. `external_readiness(tool=scout-suite, provider=aws)` when an independent implementation is useful.
4. `external_readiness(tool=powerpipe, benchmark=<approved AWS benchmark>)` for a selected benchmark pack.
5. Trivy + Checkov + Infracost against the infrastructure source tree if IaC is available.
6. `operational_readiness` when Prometheus/OpenCost evidence is configured.

### GCP and Azure

Use the same pattern: native account scan, Prowler, optional ScoutSuite/Powerpipe, then Trivy + Checkov + Infracost against IaC. Native monitoring/billing evidence should stay distinct from IaC estimates.

### GitHub / software supply chain

Run native GitHub readiness, then Prowler/Powerpipe where configured. Scan repositories with Trivy and Checkov. Do not let an account-posture scan silently gain repository-write permissions just to inspect branch/security controls.

### Kubernetes

Use the native `k8s_status` inventory plus:

- `operational_readiness` for Prometheus CPU/disk/memory/target health and OpenCost;
- Kubescape for framework/configuration controls;
- kube-bench for CIS control evidence;
- kubeaudit for workload security practices;
- Trivy for Kubernetes/Helm manifests.

These tools overlap intentionally. Agreement increases confidence; disagreement should be retained as provenance rather than averaged away.

### IaC / pre-deploy readiness

Use both Trivy and Checkov for independent policy implementations, then Infracost for cost estimation. A deployment should not be considered cost-ready merely because it passes security checks, or security-ready merely because its cost is acceptable.

## Normalization and provenance

Canonical should preserve the original tool identity for every imported finding. A normalized finding is not evidence that Canonical independently reproduced the tool's rule. The report should retain at least:

- engine name and version;
- provider/target scope;
- native rule/check id when present;
- severity/status as supplied by the engine plus Canonical's normalized severity;
- resource identifier when available;
- scan timestamp;
- parser/adapter version (the Canonical commit SHA in deployment metadata);
- whether a finding came from live account state, local IaC, cluster state, runtime telemetry, or estimated cost.

Deduplication should group related evidence but not throw away provenance. For example, a public bucket found by both Canonical and Prowler should become one remediation topic with two evidence records, not one anonymous merged record.

## Compliance posture

External compliance packs help collect evidence; they do not by themselves certify an organization. Canonical should distinguish:

- **control check passed** — the scanner observed evidence matching the rule;
- **control check failed** — machine-observable evidence conflicts with the rule;
- **unknown / unavailable** — required permission, telemetry, region, resource type, or evidence was missing;
- **manual** — organizational/process evidence cannot be established from APIs;
- **not applicable** — the control is outside the engagement scope with a documented reason.

This distinction matters for SOC 2, ISO 27001, NIST, PCI DSS, HIPAA, CIS, and similar readiness assessments.

## Installation policy

The MCP server does **not** auto-install scanners. Installation has supply-chain implications and belongs in the image/devshell/build process. Pin versions or immutable package digests in the Canonical tool image and record them in SBOM/provenance output.

Use `external_tool_status` to see which approved binaries are present. Missing tools are an availability gap, not permission to curl an installer or execute package-manager commands from MCP.
