# ADR 0001: Keep this MCP server ops-only

Status: accepted

## Decision

`canonical-mcp-server.rs` remains a local, stdio, read-only developer/operations MCP surface. It does **not** enter the customer readiness-report data plane and does not fetch or return customer report/evidence bodies.

If customer-facing readiness MCP tools become a product requirement, they belong in a distinct customer MCP service/repository with its own Shared Auth audience, deployment boundary, rate limits, audit trail, typed contracts, and customer-data threat model. Admin/destructive readiness MCP capabilities remain a third, separately privileged boundary and are not added here.

## Why

The existing server is explicitly local developer/ops tooling and already has operational credentials for bounded GitHub, Cloudflare DNS, Kubernetes and fiducia visibility. Reusing those credentials or this trust model for customer identity would collapse unrelated authority planes. A customer report tool would require session/revocation semantics, tenant-derived authorization, report-content redaction/retention rules, and a deployed network service boundary that this repository intentionally does not have.

Keeping the split means:

- ops credentials can never establish customer identity;
- customer credentials cannot invoke infrastructure tools because this repository accepts no customer credential mode;
- customer report/evidence bodies never enter local ops tool output, fixtures, logs or telemetry;
- typed readiness routes remain owned by `canonical-interfaces` and generated clients by `canonical-clients`, ready for a future customer MCP consumer without changing this repository's authority;
- destructive/admin actions stay outside the non-admin ops MCP boundary.

## Allowed readiness visibility here

Readiness-related tools may expose only operational, non-customer diagnostics that fit the existing read-only scope, such as service `/healthz`/`/readyz`, deployment/image identity, CI admission state, or aggregate component availability. They must not accept a tenant/report identifier that is treated as authorization and must not return report content, evidence payloads, R2 locators, signed URLs, database credentials, customer membership, or reviewer decisions.

## MCP surface split

| Surface | Repository/boundary | Identity | Data | Mutations |
| --- | --- | --- | --- | --- |
| Operations | this repository | local operator + read-scoped provider credentials | bounded operational metadata | none |
| Customer readiness | separate service/repository if productized | Shared Auth customer principal; tenant derived server-side | bounded customer report/workspace data through authenticated API/generated clients | only explicitly admitted customer workflow operations |
| Admin readiness | separate admin MCP boundary if needed | privileged admin identity + step-up/capability | privileged review/reconciliation metadata | explicitly audited admin actions only |

No credential is valid across these rows merely because the same human can possess both roles.

## Contract dependencies for a future customer service

A customer-facing readiness MCP implementation must wait for and consume the shared typed readiness routes/contracts from `canonical-interfaces#74/#75` and generated client surface from `canonical-clients#40`. Tool parameters may narrow or navigate an already-authorized scope but never establish tenant authority. Cross-tenant guessed IDs, revoked sessions, result bounds, and non-disclosing denial shapes belong in system tests before deployment.

## Consequences

- `canonical-mcp-server.rs#73` is resolved by choosing the ops-only option.
- No readiness report/evidence retrieval tools are added here.
- The README remains accurate: this process is local stdio developer/ops tooling, not a deployed customer application.
- Any future request to add customer report bodies here first requires replacing this ADR with an explicit architecture decision and corresponding trust/deployment changes.
