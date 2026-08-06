//! `stack_docs`: operational docs for the canonical.cloud stack. `deploy` and
//! `repo-boundaries` are fetched live from canonical-monorepo; `org-map` is
//! embedded in this binary so org-wide infra/coordination facts (GitOps
//! runtime, shared k8s libs, dpm migrations, DNS, and fiducia.cloud) are
//! available even without network access to GitHub.

use serde::Deserialize;

const RAW_ROOT: &str = "https://raw.githubusercontent.com/canonical-cloud/canonical-monorepo/main";

/// Embedded (offline) org/infra map: how canonical.cloud's own stack fits the
/// wider ORESoftware/fiducia.cloud org. Keep in sync with canonical-monorepo's
/// docs/, the marketing-site README, and k8s-cluster (last synced 2026-07).
const ORG_MAP: &str = r#"# canonical.cloud — org / infra map

canonical.cloud is a **SOC 2, FedRAMP & HIPAA compliance platform** (GitHub org
`canonical-cloud`). Repos: `canonical-monorepo` (submodule-pin superproject,
the deployable release), `canonical-web-server.rs` (Rust sMASH app server:
Supabase Auth/Postgres, Maud, Axum REST/WebSockets, SeaORM, HTMX — owns
login/session, `/app`, `/api/v1/*`, `/ws`), `canonical-marketing-site.web`
(Astro static site), `canonical-interfaces` (typed-IO source of truth: JSON
Schema for the HTTP API + the compliance-domain SQL schema, generated into
TypeScript/Rust/Rust-wasm/Python/Go adapters), and this MCP server.

## Kubernetes runtime (ORESoftware/k8s-cluster)

The stack runs on the shared EC2 Kubernetes runtime GitOps'd from
`github.com/ORESoftware/k8s-cluster` and synced by Argo CD; cluster apps live
under `remote/argocd/`, service source under `remote/deployments/`
(canonical.cloud's checkout there is a *secondary* submodule — make changes in
this org's own repos, not in that vendored copy). The workload is a single
`dd-canonical-cloud` Deployment/Service in namespace `default` on port 8119,
built in-pod (Astro frontend, then the Axum backend) with a `Recreate`
rollout strategy; a `NetworkPolicy` restricts ingress to the `dd-remote-gateway`
edge pod plus the observability scrapers (`dd-prometheus`, `dd-otel-collector`)
and confines egress to DNS and public HTTP/HTTPS. Shared cross-language
definitions (typed Postgres row adapters under `pg-defs/`, NATS subject defs,
Redis/shared interface schemas, config-client libs) live in a sibling repo,
`github.com/ORESoftware/k8s-libs-and-shared-defs`, vendored into k8s-cluster at
`remote/libs`.

## Migrations — dpm

Postgres schema changes are declarative, not imperative: `dpm`
(`github.com/declarative-migrations/declarative-postgres-migrate.rs`) diffs a
checked-in `schema.sql` (for canonical.cloud,
`canonical-web-server.rs/deploy/postgres/schema.sql`) against the live
database, verifies the plan against a throwaway shadow database, and only then
applies it under an explicit consent flag. The CLI accepts either flags or
environment variables; CI and scripts prefer the env-var form:
`SOURCE_SQL_FILE` (the desired-state file), `TARGET_DATABASE_URL` (the live
database), `SHADOW_DATABASE_URL` (a scratch server dpm can `CREATEDB` on),
`DPM_SCHEMAS` (schemas to include), and `DPM_YES` (non-interactive apply
consent) — e.g. `dpm diff`, then `dpm verify`, then `dpm apply` with those five
set. The server never migrates at boot.

## Web / DNS

Squarespace registers the org's domains; Squarespace exposes no public DNS API,
so `domain_status` reads registrar state via public RDAP instead. Live DNS
(NS/A/AAAA) and CDN/proxy delegation run through Cloudflare (account
`alexander.d.mills@gmail.com`), checked over DNS-over-HTTPS by `domain_status`
and listed directly by `cloudflare_dns`. canonical.cloud's own split differs
from the org's usual "marketing on GitHub Pages, app on a k8s Rust server"
pattern: the Astro marketing build is normally served *by*
`canonical-web-server.rs` itself (as its final static fallback for
`https://canonical.cloud`), while a separate `pages` GitHub Actions workflow
also publishes the same Astro site straight to GitHub Pages at a second
custom domain, `https://canonical.plus`, without touching the primary
`canonical.cloud` deployment.

## fiducia.cloud

`fiducia.cloud` is the org-wide shared plane for secrets (synced with GitHub
Actions secrets) and distributed locks/leases (fiducia-clients hold fenced
leases so only one instance of a singleton job runs at a time). It is
available for canonical.cloud services to adopt the same way other org repos
do; the `fiducia_status` tool checks secret *presence* and lock/lease *health*
against a configured fiducia endpoint — it never fetches secret values.

## Compliance domain

canonical.cloud's unique subject matter is the compliance-audit workflow
itself: `canonical-interfaces`' `schema/compliance.schema.json` (mirrored by
`sql/schema.sql`) defines `AuditEngagement`, a customer's compliance-audit
engagement (SOC 2 / FedRAMP / HIPAA framework selection + lifecycle status),
which `canonical-web-server.rs` serves over its versioned REST API alongside
the offline-first `draft_note` sync protocol shared with the wider stack.
"#;

/// The documents `stack_docs` can fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DocName {
    /// docs/deploy.md — how the stack is deployed.
    Deploy,
    /// docs/repo-boundaries.md — which repo owns what.
    RepoBoundaries,
    /// Embedded (offline) org/infra map: GitOps runtime, shared k8s libs, dpm
    /// migrations, Squarespace/Cloudflare DNS, and fiducia.cloud. Not fetched
    /// over the network.
    OrgMap,
}

impl DocName {
    /// Remote file name under canonical-monorepo's `docs/`, for docs fetched
    /// live over the network. `None` for embedded docs.
    fn remote_file_name(self) -> Option<&'static str> {
        match self {
            DocName::Deploy => Some("deploy.md"),
            DocName::RepoBoundaries => Some("repo-boundaries.md"),
            DocName::OrgMap => None,
        }
    }

    /// The raw.githubusercontent.com URL for a remotely-fetched doc; `None`
    /// for embedded docs.
    pub fn url(self) -> Option<String> {
        self.remote_file_name()
            .map(|name| format!("{RAW_ROOT}/docs/{name}"))
    }

    /// Embedded doc text for docs that don't live in canonical-monorepo.
    fn embedded(self) -> Option<&'static str> {
        match self {
            DocName::OrgMap => Some(ORG_MAP),
            DocName::Deploy | DocName::RepoBoundaries => None,
        }
    }
}

/// Fetch the markdown for `doc`. Embedded docs (`org-map`) return instantly
/// and never touch the network; the others are fetched live from
/// canonical-monorepo.
pub async fn fetch(client: &reqwest::Client, doc: DocName) -> Result<String, String> {
    if let Some(text) = doc.embedded() {
        return Ok(text.to_string());
    }
    let url = doc.url().expect("non-embedded DocName has a url");
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("GET {url} failed: {}", super::error_chain(&error)))?;
    let status = response.status();
    let body = super::read_body_capped(response, super::MAX_RESPONSE_BYTES)
        .await
        .map_err(|error| format!("GET {url}: {error}"))?;
    if !status.is_success() {
        return Err(format!("GET {url} returned {status}"));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_urls_point_at_monorepo_docs() {
        assert_eq!(
            DocName::Deploy.url().as_deref(),
            Some("https://raw.githubusercontent.com/canonical-cloud/canonical-monorepo/main/docs/deploy.md")
        );
        assert_eq!(
            DocName::RepoBoundaries.url().as_deref(),
            Some("https://raw.githubusercontent.com/canonical-cloud/canonical-monorepo/main/docs/repo-boundaries.md")
        );
    }

    #[test]
    fn org_map_is_embedded_not_fetched() {
        assert_eq!(DocName::OrgMap.url(), None);
        assert_eq!(DocName::OrgMap.embedded(), Some(ORG_MAP));
    }

    #[test]
    fn doc_name_deserializes_kebab_case() {
        assert_eq!(
            serde_json::from_str::<DocName>("\"deploy\"").unwrap(),
            DocName::Deploy
        );
        assert_eq!(
            serde_json::from_str::<DocName>("\"repo-boundaries\"").unwrap(),
            DocName::RepoBoundaries
        );
        assert_eq!(
            serde_json::from_str::<DocName>("\"org-map\"").unwrap(),
            DocName::OrgMap
        );
        assert!(serde_json::from_str::<DocName>("\"nope\"").is_err());
    }

    #[test]
    fn org_map_covers_stack_knowledge() {
        for needle in [
            "ORESoftware/k8s-cluster",
            "Argo CD",
            "dd-canonical-cloud",
            "ORESoftware/k8s-libs-and-shared-defs",
            "declarative-migrations/declarative-postgres-migrate.rs",
            "SOURCE_SQL_FILE",
            "TARGET_DATABASE_URL",
            "SHADOW_DATABASE_URL",
            "DPM_SCHEMAS",
            "DPM_YES",
            "Squarespace",
            "Cloudflare",
            "alexander.d.mills@gmail.com",
            "canonical.plus",
            "fiducia.cloud",
            "locks/leases",
            "SOC 2",
            "FedRAMP",
            "HIPAA",
            "AuditEngagement",
        ] {
            assert!(ORG_MAP.contains(needle), "org_map missing {needle:?}");
        }
    }
}
