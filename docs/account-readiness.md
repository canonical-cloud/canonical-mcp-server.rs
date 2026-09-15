# Account readiness scanning

`canonical-mcp-server` exposes a strict read-only posture scanner for customer cloud and hosting accounts. The scanner returns evidence, a 0–100 posture score, prioritized findings, and remediation advice; it never applies the advice itself.

## Supported providers

The native matrix is AWS, GCP, Azure, Cloudflare, GitHub, Upstash Redis, Vercel, DigitalOcean, Netlify, Render, Fly.io, and Heroku.

Use the MCP `readiness_catalog` tool to retrieve the current provider/credential matrix. Use `account_readiness` for API/CLI evidence and `browser_readiness` only when a provider exposes important console-only evidence.

Native account evidence is intentionally complemented by two independent layers:

- `operational_readiness` reads fixed Prometheus/OpenCost signals for actual CPU, filesystem free space, memory pressure, target health, and Kubernetes cost allocation. See `docs/operational-readiness.md`.
- `external_readiness` runs fixed adapters for Prowler, ScoutSuite, Trivy, Checkov, Kubescape, kube-bench, kubeaudit, Infracost, and Powerpipe. See `docs/open-source-parity.md`.

The goal is not to collapse every engine into one opaque score. Canonical retains provenance so native provider evidence, open-source rule-engine findings, live metrics, IaC findings, and cost estimates can corroborate or contradict one another explicitly.

## Non-negotiable read-only contract

The implementation is fail-closed:

- SaaS integrations have no generic HTTP method or URL primitive. They use hard-coded HTTPS API hostname allowlists and `GET` only.
- AWS, GCP, Azure, and Fly.io integrations spawn exact read/list/describe CLI command families directly; no shell is invoked and no arbitrary command is accepted.
- The MCP surface exposes scan/catalog/status/browser tools only; there is no deploy, create, update, delete, restart, rotate-secret, scale, or write tool.
- Responses are capped and bearer-token API calls use the MCP server's no-redirect client, preventing Authorization headers from following redirects to attacker-controlled hosts.
- Tokens, cookies, and secret values are never returned as findings and must never be logged.
- Browser automation performs zero clicks and zero form submissions. It aborts every request whose method is not GET, HEAD, or OPTIONS and blocks top-level navigation outside the provider's console/authentication hostname allowlist.
- Browser mode therefore requires an already-authenticated Playwright storage state or Puppeteer profile where login itself needs a POST. This is deliberate: the scanner will not weaken the write barrier just to authenticate.
- Prometheus/OpenCost endpoints are operator environment configuration, not MCP parameters; remote endpoints require HTTPS, fixed queries use GET only, and callers cannot supply PromQL.
- External scanners use compiled executable/argument grammars. There is no generic shell/command/argument array. Local scan targets must stay under `CANONICAL_AUDIT_ROOT`.

The strongest deployment model combines the code-level write barrier with provider-level least privilege. Where a provider offers a native read-only role or token, use it even though the scanner itself cannot issue a write.

## Least-privilege baseline

| Provider | Credential / identity | Baseline |
| --- | --- | --- |
| AWS | normal AWS CLI/SDK credential chain | `SecurityAudit` plus CloudWatch read-only and the minimum Cost Explorer/Budgets read actions required by the engagement; never AdministratorAccess |
| GCP | gcloud/ADC identity | project Viewer plus Monitoring Viewer, Cloud Asset Viewer, Billing Account Viewer, and Recommender Viewer only where those evidence families are requested |
| Azure | Azure CLI identity | Reader + Monitoring Reader + Cost Management Reader; never Contributor/Owner for scans |
| Cloudflare | `CLOUDFLARE_API_TOKEN` | only required Account/Zone `Read` permission groups; never Global API Key |
| GitHub | `GITHUB_TOKEN` or `GH_TOKEN` | fine-grained PAT or GitHub App with only required repository/organization read permissions |
| Upstash | `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_READ_ONLY_TOKEN` | the Upstash Read Only REST token only; the Standard token is intentionally unsupported |
| Vercel | `VERCEL_AUDIT_TOKEN` | dedicated audit identity/team scope; scanner has GET-only transport |
| DigitalOcean | `DIGITALOCEAN_READ_ONLY_TOKEN` | Read Only / `api:read`, optionally narrower resource `:read` scopes |
| Netlify | `NETLIFY_AUDIT_TOKEN` | dedicated audit identity/token; scanner has GET-only transport |
| Render | `RENDER_AUDIT_TOKEN` | dedicated audit identity/API key; scanner has GET-only transport |
| Fly.io | flyctl credential | dedicated audit identity/token; only allowlisted read commands are invoked |
| Heroku | `HEROKU_READ_ONLY_TOKEN` | OAuth token created with the `read` scope |

External tools inherit their normal provider credentials. The Canonical wrapper prevents caller-controlled mutation commands, but it cannot make an overprivileged AWS/GCP/Azure/etc credential read-only. Provider-level least privilege remains mandatory.

## Finding families

Every provider maps evidence into the same categories: identity/access, resource inventory, security baseline, reliability/backups, utilization/capacity, budget/cost, and observability.

Implemented checks include examples such as:

- AWS: IMDSv2 requirement, public EC2 addresses, EBS encryption, unattached EBS volumes, firing CloudWatch alarms (CPU/disk/memory alarms are elevated), and current-month Cost Explorer spend.
- GCP: Compute Engine external addresses and unattached persistent disks, with explicit guidance for Monitoring/Billing evidence.
- Azure: VM public addresses, unattached managed disks, consumption records, and Azure Advisor recommendations.
- Cloudflare: account/zone inventory and non-active zones.
- GitHub: repository inventory plus selected repository hygiene findings; additional security/billing/audit-log checks remain permission-gated.
- Upstash: Redis memory pressure and evictions using the read-only REST token.
- Vercel: project/deployment inventory and failed/canceled deployment evidence.
- DigitalOcean: Droplet backup posture, unattached block volumes, and month-to-date billing usage.
- Netlify: site inventory and forced-HTTPS posture.
- Render/Fly.io/Heroku: inventory and provider-specific health/posture evidence available through read-only surfaces.

## Capacity and low-disk rules

A scanner must distinguish **unknown** from **healthy**. Provisioned disk size is not filesystem free space. The native provider scanner therefore does not infer low-disk health from EBS/Persistent Disk/Managed Disk allocation.

When `CANONICAL_PROMETHEUS_URL` is configured, `operational_readiness` closes that gap with real node-exporter evidence:

- five-minute host CPU percentage;
- filesystem available percentage from `node_filesystem_avail_bytes / node_filesystem_size_bytes`;
- available-memory percentage;
- `up == 0` scrape-target health.

Default thresholds are CPU >=85% high / >=95% critical, filesystem free <=15% high / <=5% critical, and available memory <=15% high / <=5% critical. They are operator-configurable through the documented environment variables.

When metrics are absent, the report says `unknown`; it does not fabricate health from inventory.

## Budget and FinOps evidence

Set a per-provider monthly budget with `CANONICAL_<PROVIDER>_MONTHLY_BUDGET_USD`, for example `CANONICAL_AWS_MONTHLY_BUDGET_USD=2500`. `CANONICAL_READINESS_MONTHLY_BUDGET_USD` is the fallback.

Where the provider supplies comparable spend evidence, the current thresholds are:

- 70% of budget: medium
- 85%: high
- 100% or greater: critical

For Kubernetes, OpenCost adds month-window namespace allocation evidence and can compare it with `CANONICAL_KUBERNETES_MONTHLY_BUDGET_USD`. Infracost adds a different signal: pre-deploy monthly estimates from IaC. Use both actual allocation and shift-left estimates when available.

The recommendation remains advisory: identify dominant cost centers, idle resources, egress/storage growth, autoscaling limits, requests/limits, and reservation/commitment opportunities. The scanner never deletes, downsizes, stops, or changes a resource.

## Open-source cross-checks

Use `external_tool_status` to discover which approved engines are installed and `external_tool_catalog` for their fixed invocation/safety matrix.

Recommended layers include:

- Prowler for broad multi-cloud security/compliance coverage;
- ScoutSuite as an independent cloud configuration/attack-surface implementation;
- Trivy + Checkov for overlapping IaC policy coverage;
- Kubescape + kube-bench + kubeaudit for Kubernetes framework/CIS/workload coverage;
- Infracost for IaC cost estimation;
- Powerpipe/Steampipe for benchmark-as-code over read-only connections.

Tool installation is deliberately not an MCP capability. Pin and verify external binaries in the build/devshell/container supply chain.

## Browser fallback

Install the browser dependencies when browser evidence is required:

```sh
npm install
npx playwright install chromium
npm run browser:test
```

Playwright may use `CANONICAL_PLAYWRIGHT_STORAGE_STATE` to point at an already-authenticated storage-state file. Puppeteer may use `CANONICAL_PUPPETEER_USER_DATA_DIR` for an already-authenticated profile. Treat either artifact as sensitive customer material and keep it outside source control.

Console SPAs that require POST requests even for read-only GraphQL/RPC fetches may not render completely because the browser interceptor blocks those requests. That is an intentional fail-closed behavior; prefer the provider API/CLI collector instead of relaxing the browser policy.

## MCP examples

- `readiness_catalog`: no parameters; returns the 12-provider matrix.
- `account_readiness`: `provider=aws` for the currently configured AWS audit identity.
- `account_readiness`: `provider=gcp, scope=my-project-id` without changing the active gcloud project.
- `account_readiness`: `provider=azure, scope=<subscription-id>` without changing the active subscription.
- `account_readiness`: `provider=github, scope=customer-org`.
- `operational_readiness`: no parameters; uses configured Prometheus/OpenCost endpoints if present.
- `external_tool_status`: no parameters; fixed local version probes only.
- `external_readiness`: `tool=prowler, provider=aws`.
- `external_readiness`: `tool=checkov, target=infra/` where `infra/` resolves under `CANONICAL_AUDIT_ROOT`.
- `external_readiness`: `tool=infracost, target=infra/terraform/`.
- `external_readiness`: `tool=powerpipe, benchmark=aws_compliance.benchmark.cis_v400`.
- `browser_readiness`: `provider=cloudflare, engine=playwright`; intended only for console-only evidence gaps.

Tests must remain network-free. Provider/Prometheus/OpenCost/external response interpretation should stay in pure functions/fixtures; live account access belongs only in thin orchestration layers.
