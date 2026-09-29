# Conformance

`contracts/` owns structure/wire shape; `conformance/` owns implementation-neutral behavioral expectations and promotion evidence.

- Every maintained participant claiming the behavior consumes the same shared case/fixture bytes.
- Shared behavior does not get implementation-local golden corpora.
- Evidence is bound to exact contract inputs and case revisions/digests; stale evidence fails closed.
- Missing evidence from a required participant is a failure, not a skip.
- Reports, receipts, snapshots, and parity artifacts are evidence only.
- Scaffold-only coverage is explicit; equivalence is not claimed until domain cases run across required participants.
- Unexplained contract/conformance/runtime drift blocks release.

Add `conformance/manifest.v1.json` as the executable participant/admission/coverage/digest manifest.
