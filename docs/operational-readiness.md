# Operational readiness with Prometheus and OpenCost

Cloud inventory alone cannot prove that a running system has enough CPU, memory, or filesystem headroom. `operational_readiness` therefore consumes read-only evidence from two open-source systems when the operator configures them:

- **Prometheus** — fixed instant-query `GET /api/v1/query` requests for CPU utilization, real filesystem available percentage, available-memory percentage, and scrape target health.
- **OpenCost** — fixed `GET /allocation` month-window allocation query aggregated by Kubernetes namespace.

The MCP caller does not provide a URL or PromQL expression. Endpoints and optional bearer tokens are operator-owned environment configuration, and Canonical issues GET requests only.

## Environment

```text
CANONICAL_PROMETHEUS_URL=https://prometheus.example.internal
CANONICAL_PROMETHEUS_BEARER_TOKEN=...        # optional

CANONICAL_OPENCOST_URL=https://opencost.example.internal
CANONICAL_OPENCOST_BEARER_TOKEN=...          # optional

CANONICAL_CPU_HIGH_PERCENT=85                # optional; 1..100
CANONICAL_DISK_FREE_LOW_PERCENT=15           # optional; 0.1..99
CANONICAL_MEMORY_FREE_LOW_PERCENT=15         # optional; 0.1..99
CANONICAL_KUBERNETES_MONTHLY_BUDGET_USD=500 # optional
```

Remote endpoints must use HTTPS. Plain HTTP is accepted only for loopback (`localhost`, `127.0.0.1`, `::1`) so an operator can use a local port-forward without weakening remote transport requirements. Embedded `user:password@host` URL credentials are rejected; use a dedicated read-only proxy or the optional bearer-token environment variables instead.

## Prometheus evidence

The collector uses fixed expressions derived from node-exporter metrics:

- CPU: five-minute non-idle percentage from `node_cpu_seconds_total`.
- Filesystem: `node_filesystem_avail_bytes / node_filesystem_size_bytes`, excluding common ephemeral/read-only filesystem types.
- Memory: `node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes`.
- Target health: `up == 0`.

Default finding thresholds:

| Signal | High | Critical |
| --- | ---: | ---: |
| CPU utilization | >= 85% | >= 95% |
| Filesystem free | <= 15% | <= 5% |
| Available memory | <= 15% | <= 5% |
| Prometheus target down | high | — |

This gives Canonical a defensible low-disk check: it uses actual filesystem telemetry rather than pretending that a cloud disk's provisioned size tells us its free space.

Missing metrics are `unknown`, not `pass`. If node-exporter is not deployed, a storage resource should not be marked healthy merely because the provider API is reachable.

Prometheus's HTTP API supports instant expressions over `GET /api/v1/query`; Canonical deliberately uses only that read form even if a Prometheus release also permits POST. Queries are compiled into the binary and URL-encoded by the HTTP client.

## OpenCost evidence

The collector performs a fixed GET to the OpenCost allocation API with:

```text
window=month
aggregate=namespace
includeIdle=true
```

It reports the observed namespace count and month-window allocation total. It also raises:

- a concentration finding when one namespace accounts for at least 50% of observed allocation cost and multiple namespaces exist;
- budget findings at 70% / 85% / 100% of `CANONICAL_KUBERNETES_MONTHLY_BUDGET_USD`.

OpenCost allocation is operational cost evidence, while Infracost is pre-deploy IaC estimation. Use both; they answer different questions.

## Recommended monitoring cross-check

For Kubernetes production readiness, combine:

1. `k8s_status` — direct cluster inventory/readiness state.
2. `operational_readiness` — Prometheus CPU/disk/memory/target evidence + OpenCost allocation.
3. `external_readiness(tool=kubescape)` — security/framework posture.
4. `external_readiness(tool=kube-bench)` — CIS benchmark evidence.
5. `external_readiness(tool=kubeaudit)` — workload hardening.
6. `external_readiness(tool=trivy, target=...)` — deployment/IaC configuration.
7. `external_readiness(tool=infracost, target=...)` — shift-left cost estimation when Terraform is available.

Overlapping signals are desirable. Canonical should preserve source provenance instead of silently averaging different tools into one opaque score.

## Security model

Prometheus can contain operationally sensitive labels and OpenCost can expose spend/topology information. Treat these endpoints as customer evidence systems:

- give the Canonical process read-only credentials;
- scope network access to the explicit endpoint;
- do not expose Prometheus admin/write endpoints;
- do not return bearer tokens or query credentials in findings/logs;
- prefer dedicated audit identities where the proxy/identity layer supports them;
- retain only the evidence required by the engagement.
