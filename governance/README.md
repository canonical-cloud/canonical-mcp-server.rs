# Governance

Contract/conformance boundaries are governed explicitly.

- Every shared interface has exactly one canonical repository owner.
- Material changes record the decision, alternatives, compatibility impact, migration/rollback path, and conformance evidence.
- Adding/removing a runtime, language, client, adapter, or persistence projection requires the matching participant/admission update.
- Generated artifacts cannot become a second source of truth.
- CI/promotion fails closed on missing or stale required evidence; exceptions name an owner, scope, rationale, and expiry/revisit condition.
- Emergency changes reconcile authority/evidence before the next release.

When multiple maintained participants exist, add a machine-readable `governance/*.v1.json` registry and make CI prove it matches the conformance manifest and admission workflow.
