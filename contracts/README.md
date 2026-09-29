# Contract authority

`contracts/` is the human-authored authority boundary for API, wire, persistence, configuration, and cross-process shapes owned here.

- TypeSpec and JSON Schema/OpenAPI are independent peer authorities when both are used; neither is generated from the other and promoted as canonical.
- Generated SDKs, types, ORM projections, docs, and runtime descriptors are evidence/projections, not authority.
- Material changes state compatibility impact and the conformance evidence required for promotion.
- Unexplained authority/projection/runtime drift fails closed; never auto-resolve it by regenerating one authority from another.
- Cross-repository interfaces have exactly one canonical owner; mirrors and consumers do not silently fork them.

Until domain-specific artifacts exist here, this establishes an authority boundary only and claims no behavioral coverage.
