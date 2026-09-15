# ADR 0001: Keep this MCP server ops-only

Status: accepted

## Decision

`canonical-mcp-server.rs` remains a local, stdio, read-only developer/operations MCP surface. It is not a customer-authenticated readiness service and does not enter the customer readiness-report/workspace data plane.

Operator-initiated, read-only scans of explicitly configured provider accounts are allowed here. Those scans use operator-supplied, provider-scoped credentials to collect bounded infrastructure/account metadata and produce advisory posture findings. That provider access is an operations/audit capability; it does not establish customer identity, tenant membership, or authorization to customer report/workspace data.

If customer-facing readiness MCP tools become a product requirement, they belong in a distinct customer MCP service/repository with its own Shared Auth audience, deployment boundary, rate limits, audit trail, typed contracts, and customer-data threat model. Admin/destructive readiness MCP capabilities remain a third, separately privileged boundary and are not added here.

## Trust boundaries

The following invariants are mandatory:

- provider credentials authorize only the provider reads that the local operator has deliberately configured; they never establish a Canonical customer principal or tenant;
- this process accepts no customer session/cookie mode and no tenant/report identifier may be treated as authorization;
- account-readiness tools may return bounded provider resource/account metadata and derived findings, but not Canonical customer report/evidence bodies, R2 locators, signed URLs, customer membership, reviewer decisions, or database credentials;
- SaaS adapters remain GET-only against compiled HTTPS host allowlists;
- CLI-backed adapters remain fixed read/list/describe command families with no shell or caller-controlled executable/argument array;
- browser fallback remains observation-only: no clicks/forms, no mutation methods, and no cross-provider top-level navigation;
- provider credentials should be genuinely read-only where the provider supports that. A code-level GET/read barrier does not make an overprivileged credential least-privilege;
- destructive/admin actions stay outside this repository.

## MCP surface split

| Surface | Repository/boundary | Identity | Data | Mutations |
| --- | --- | --- | --- | --- |
| Operations/provider audit | this repository | local operator + read-scoped provider credentials | bounded infrastructure/account metadata and derived readiness findings | none |
| Customer readiness | separate service/repository if productized | Shared Auth customer principal; tenant derived server-side | bounded customer report/workspace data through authenticated API/generated clients | only explicitly admitted customer workflow operations |
| Admin readiness | separate admin MCP boundary if needed | privileged admin identity + step-up/capability | privileged review/reconciliation metadata | explicitly audited admin actions only |

No credential is valid across these rows merely because the same human can possess both roles.

## Customer-data boundary

This repository must not grow tools that retrieve Canonical readiness report bodies, evidence payloads, report content, customer membership, or reviewer decisions. Shared readiness routes remain owned by `canonical-interfaces` and generated clients by `canonical-clients`; a future customer-facing MCP service must consume those contracts behind Shared Auth and server-derived tenant authorization.

Cross-tenant guessed IDs, revoked sessions, result bounds, and non-disclosing denial shapes belong in that separate service's system tests before deployment.

## Consequences

- The multi-cloud account scanner is an ops/audit tool, even when an operator is assessing an account owned by or delegated from a customer.
- The README and scanner documentation must describe operator-configured provider access rather than implying that this stdio process is a customer-facing application.
- No readiness report/evidence retrieval tools are added here.
- Any future request to make this process customer-facing first requires replacing this ADR with an explicit architecture decision and corresponding identity, deployment, authorization, retention, and threat-model changes.
