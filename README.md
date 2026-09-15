# canonical-mcp-server.rs

An [MCP](https://modelcontextprotocol.io) (Model Context Protocol) server for
operating and auditing the **[canonical.cloud](https://canonical.cloud)** stack
(GitHub org [`canonical-cloud`](https://github.com/canonical-cloud)). It runs
locally over stdio and gives an MCP client read-only visibility into CI,
submodule pins, deployment health, cloud/account readiness, and operational
docs.

Built on the official Rust MCP SDK
([`rmcp`](https://github.com/modelcontextprotocol/rust-sdk)) with a tokio
runtime and reqwest (rustls, no OpenSSL).

## Tools

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `readiness_catalog` | — | Offline matrix for the 12 native account providers, credentials, least-privilege guidance, and check families |
| `account_readiness` | `provider`; `scope` optional | Strict read-only native account scan for AWS, GCP, Azure, Cloudflare, GitHub, Upstash, Vercel, DigitalOcean, Netlify, Render, Fly.io, or Heroku |
| `operational_readiness` | — | Fixed read-only Prometheus/OpenCost evidence for high CPU, real filesystem free space, memory pressure, scrape-target health, Kubernetes allocation cost, and budget pressure |
| `external_tool_catalog` | — | Offline capability/safety matrix for the supported open-source scanners |
| `external_tool_status` | — | Fixed local version probes showing which approved scanners are installed; does not access customer accounts |
| `external_readiness` | `tool`; `provider`, `target`, `benchmark` as applicable | Run a fixed adapter for Prowler, ScoutSuite, Trivy, Checkov, Kubescape, kube-bench, kubeaudit, Infracost, or Powerpipe |
| `browser_readiness` | `provider`, `engine`; `url` optional | Playwright/Puppeteer console fallback that performs no clicks/forms and blocks non-read HTTP methods/cross-provider navigation |
| `stack_ci_status` | `repo` optional | Latest five GitHub Actions runs per stack repo: branch, status, conclusion, workflow, run URL, timestamp |
| `submodule_pins` | — | Compare `canonical-monorepo` app submodule pins against each app repo's `main` HEAD |
| `service_health` | `base_url` | Probe `{base}/healthz`, `{base}/readyz`, `{base}/api/v1/health` with bounded response bodies |
| `stack_docs` | `doc`: `deploy` \| `repo-boundaries` \| `org-map` | Fetch operational docs or embedded org/infra knowledge |
| `domain_status` | `domain` default `canonical.cloud` | Registrar state via RDAP plus live NS/A/AAAA DNS state |
| `cloudflare_dns` | `domain` default `canonical.cloud` | Read-only Cloudflare DNS record inventory |
| `k8s_status` | `resource`; `namespace`, `context` optional | Read-only allowlisted `kubectl get … -o json` cluster state |
| `fiducia_status` | — | Read-only required-secret *presence* and lock/lease health; never secret values |

See [`docs/account-readiness.md`](docs/account-readiness.md) for the native
provider model, [`docs/open-source-parity.md`](docs/open-source-parity.md) for
the open-source scanner parity/cross-check architecture, and
[`docs/operational-readiness.md`](docs/operational-readiness.md) for
Prometheus/OpenCost evidence and thresholds.

The stack repositories covered by `stack_ci_status` are
`canonical-monorepo`, `canonical-web-server.rs`,
`canonical-marketing-site.web`, and `canonical-interfaces`.

## Read-only account-audit contract

The native account scanner is fail-closed:

- SaaS adapters issue `GET` requests only to compiled HTTPS host allowlists.
- AWS/GCP/Azure/Fly adapters invoke exact read/list/describe CLI command
  families without a shell or caller-supplied arbitrary arguments.
- Browser mode aborts non-GET/HEAD/OPTIONS requests and performs no clicks or
  form submissions.
- Prometheus/OpenCost endpoints come only from operator-owned environment
  configuration, use fixed GET queries, and do not accept caller-supplied
  PromQL or URLs.
- No MCP tool can create, deploy, update, delete, restart, scale, rotate
  secrets, or otherwise mutate customer resources.
- Tokens and secret values are never returned or logged.

The open-source adapter follows the same boundary at the orchestration layer:
there is no generic executable, shell, argument array, URL, or environment
parameter. Each tool has a compiled executable/argument grammar. Cloud scanners
inherit the process's provider credential, so that credential **must also be
restricted read-only at the provider**.

External tool installation is deliberately outside MCP. Pin scanner versions or
immutable images in the devshell/container/build process and use
`external_tool_status` to verify what is present.

## Running

```sh
cargo run
cargo run -- --log-filter=debug,hyper=warn
```

The binary audits `.cli-flags.toml` before telemetry or MCP startup. Set
`CANONICAL_FLAGS_CONFIG` when an installed binary cannot discover the contract
from the current directory, executable directory, or
`../share/canonical-mcp-server`. Only the non-secret log filter is accepted as
a flag.

The server speaks MCP over stdin/stdout; it is meant to be launched by an MCP
client, not used interactively.

### Register in Claude Code

From a checkout, using the debug build via cargo:

```sh
claude mcp add canonical-mcp -- cargo run \
  --manifest-path /path/to/canonical-mcp-server.rs/Cargo.toml
```

Or build once and register the release binary:

```sh
cargo build --release
claude mcp add canonical-mcp -- \
  /path/to/canonical-mcp-server.rs/target/release/canonical-mcp-server
```

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` / `GH_TOKEN` | for authenticated GitHub scans | Read-scoped GitHub credential |
| `CLOUDFLARE_API_TOKEN` | for Cloudflare scans | Cloudflare API token containing only required `Read` groups |
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_READ_ONLY_TOKEN` | for Upstash | Read-only Redis REST endpoint/token; the standard write-capable token is intentionally unsupported |
| `VERCEL_AUDIT_TOKEN` | for Vercel | Dedicated audit identity/token; Canonical issues GET only |
| `DIGITALOCEAN_READ_ONLY_TOKEN` | for DigitalOcean | DigitalOcean Read Only / `api:read` credential |
| `NETLIFY_AUDIT_TOKEN` | for Netlify | Dedicated audit identity/token; Canonical issues GET only |
| `RENDER_AUDIT_TOKEN` | for Render | Dedicated audit identity/API key; Canonical issues GET only |
| `HEROKU_READ_ONLY_TOKEN` | for Heroku | OAuth token created with `read` scope |
| normal AWS CLI credential chain | for AWS | Audit role, never AdministratorAccess |
| normal gcloud/ADC identity | for GCP | Viewer/Monitoring/Asset/Billing/Recommender read roles as required |
| normal Azure CLI identity | for Azure | Reader + Monitoring Reader + Cost Management Reader |
| flyctl credential | for Fly.io | Dedicated audit identity; Canonical invokes only allowlisted read commands |
| `KUBECONFIG` / kubeconfig | for Kubernetes scans | Read-only RBAC for `get`/`list`/`watch` where external cluster scanners are used |
| `CANONICAL_<PROVIDER>_MONTHLY_BUDGET_USD` | optional | Per-provider monthly budget for native spend-utilization findings |
| `CANONICAL_READINESS_MONTHLY_BUDGET_USD` | optional | Global budget fallback |
| `CANONICAL_PROMETHEUS_URL` | for Prometheus operational evidence | Operator-configured HTTPS endpoint; loopback HTTP is allowed for port-forwarding |
| `CANONICAL_PROMETHEUS_BEARER_TOKEN` | optional | Read-only proxy/API bearer token; never returned/logged |
| `CANONICAL_OPENCOST_URL` | for OpenCost operational evidence | Operator-configured HTTPS endpoint; loopback HTTP is allowed for port-forwarding |
| `CANONICAL_OPENCOST_BEARER_TOKEN` | optional | Read-only proxy/API bearer token; never returned/logged |
| `CANONICAL_CPU_HIGH_PERCENT` | optional | High-CPU threshold; default 85 |
| `CANONICAL_DISK_FREE_LOW_PERCENT` | optional | Low-filesystem-free threshold; default 15 |
| `CANONICAL_MEMORY_FREE_LOW_PERCENT` | optional | Low-available-memory threshold; default 15 |
| `CANONICAL_KUBERNETES_MONTHLY_BUDGET_USD` | optional | Budget for OpenCost month-window allocation findings |
| `CANONICAL_AUDIT_ROOT` | for local external scans when cwd is not the desired root | Filesystem root beneath which Trivy/Checkov/Kubescape/kubeaudit/Infracost targets must resolve; default `.` |
| `CANONICAL_EXTERNAL_TOOL_TIMEOUT_SECS` | optional | External scanner timeout, clamped to 10–600 seconds; default 180 |
| `CANONICAL_PLAYWRIGHT_STORAGE_STATE` | optional browser fallback | Sensitive pre-authenticated Playwright state file |
| `CANONICAL_PUPPETEER_USER_DATA_DIR` | optional browser fallback | Sensitive pre-authenticated Puppeteer profile directory |
| `FIDUCIA_URL` + `FIDUCIA_TOKEN` | for `fiducia_status` | Base URL and read-scoped bearer token for fiducia.cloud |
| `FIDUCIA_REQUIRED_SECRETS` | optional | Comma-separated secret names for `fiducia_status` to assert present |

Native bearer-token HTTP requests use a no-redirect client and bounded response
bodies. Public/token-less endpoints use the normal bounded client. External
scanner binaries may make their own provider/network requests according to the
upstream tool; that is why Canonical pins the executable/argument surface and
requires provider-level read-only credentials in addition to its own adapter
barrier.

## Layout

- `src/main.rs` — bootstrap only; serves the handler over stdio.
- `src/server.rs` — tool router, parameter schemas, `ServerHandler`.
- `src/tools/readiness.rs` — native twelve-provider readiness collectors,
  normalized findings, budget/utilization logic, browser orchestration.
- `src/tools/observability.rs` — fixed Prometheus/OpenCost operational evidence.
- `src/tools/external.rs` — fixed open-source scanner adapters and parsers.
- `src/tools/external_status.rs` — fixed scanner version/install probes.
- `src/tools/github.rs` — GitHub client plus pure JSON summarization.
- `src/tools/health.rs` — endpoint probing and body truncation.
- `src/tools/docs.rs` — monorepo docs plus embedded org/infra knowledge.
- `src/tools/domain.rs` — RDAP + DNS-over-HTTPS summarization and validation.
- `src/tools/cloudflare.rs` — Cloudflare zone/record listing.
- `src/tools/fiducia.rs` — fiducia.cloud secret-presence and lock/lease checks.
- `src/tools/k8s.rs` — allowlisted `kubectl get` runner and summarizers.
- `browser/readiness-audit.mjs` — Playwright/Puppeteer read-only browser guard.

Response interpretation should remain pure and fixture-testable. Live account
access belongs in thin orchestration functions, and tests must not depend on
customer networks/accounts.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
npm run browser:test
```

The Nix dev shell mirrors the sibling repos: `./shell` drops you into it
(requires Nix with flakes).

## OpenTelemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export explicit OTLP/gRPC traces and
metrics; use `RUST_LOG` for filtering. Each MCP tool call gets a named span,
call counter, duration histogram, and error flag. Arguments, results, and
secrets are never recorded. JSON logs stay on stderr and stdout stays reserved
for MCP framing. Instrumentation is explicit Rust code—no monkey patching.
