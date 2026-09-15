//! The MCP server: tool routing and the `ServerHandler` implementation.

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ErrorData, ServerHandler,
};
use serde::Deserialize;

use crate::tools::{cloudflare, docs, domain, fiducia, github, health, k8s, readiness};

pub struct CanonicalMcp {
    /// Redirect-following client for token-less endpoints: RDAP (rdap.org
    /// intentionally redirects to the authoritative server), DNS-over-HTTPS,
    /// operator-supplied health URLs, and raw doc fetches.
    http: reqwest::Client,
    /// No-redirect client for every request that carries a bearer token
    /// (GitHub, Cloudflare, fiducia, and account-readiness providers). These
    /// APIs never legitimately redirect, and refusing to follow one prevents a
    /// hijacked/open redirect from replaying Authorization to another host.
    api_http: reqwest::Client,
    github: github::GitHubClient,
    tool_router: ToolRouter<Self>,
}

impl CanonicalMcp {
    pub fn new() -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(github::USER_AGENT)
            .build()?;
        let api_http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(github::USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            github: github::GitHubClient::new(api_http.clone()),
            http,
            api_http,
            tool_router: crate::telemetry::instrument_tool_router(Self::tool_router()),
        })
    }
}

fn json_result(value: &impl serde::Serialize) -> Result<CallToolResult, ErrorData> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn tool_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StackCiStatusParams {
    /// Limit the report to one repository (e.g. "canonical-web-server.rs").
    /// Omit to report on every stack repository.
    pub repo: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceHealthParams {
    /// Base URL of the deployment to probe, e.g. "https://canonical.cloud".
    pub base_url: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StackDocsParams {
    /// Which document to fetch: "deploy", "repo-boundaries" (both live in
    /// canonical-monorepo), or "org-map" (embedded org/infra knowledge).
    pub doc: docs::DocName,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DomainStatusParams {
    /// Domain to inspect. Defaults to "canonical.cloud".
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CloudflareDnsParams {
    /// Zone (apex domain) whose DNS records to list. Defaults to "canonical.cloud".
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct K8sStatusParams {
    /// Resource to inspect: nodes, pods, deployments, services, or ingresses.
    pub resource: k8s::K8sResource,
    /// Namespace to scope to. Omit for all namespaces.
    pub namespace: Option<String>,
    /// kubeconfig context to use. Omit for the current context.
    pub context: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AccountReadinessParams {
    /// Provider to audit. Supported: aws, gcp, azure, cloudflare, github,
    /// upstash, vercel, digital-ocean, netlify, render, fly-io, heroku.
    pub provider: readiness::Provider,
    /// Optional provider scope: GCP project id, Azure subscription id,
    /// GitHub organization, or Fly.io organization. Omit where not needed.
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BrowserReadinessParams {
    /// Provider console to inspect with strict read-only browser automation.
    pub provider: readiness::Provider,
    /// Browser engine: playwright or puppeteer.
    pub engine: readiness::BrowserEngine,
    /// Optional allowlisted console URL. Omit to use the provider dashboard.
    pub url: Option<String>,
}

#[tool_router]
impl CanonicalMcp {
    #[tool(
        description = "Read-only cloud/account posture scan for AWS, GCP, Azure, Cloudflare, \
                       GitHub, Upstash Redis, Vercel, DigitalOcean, Netlify, Render, Fly.io, \
                       or Heroku. Collects inventory/security/reliability/utilization/cost evidence \
                       using only allowlisted GET endpoints or exact read/list/describe CLI API \
                       commands, then emits prioritized findings and remediation advice. The \
                       scanner has no generic URL, HTTP method, shell, deploy, update, delete, \
                       restart, secret-write, or resource-mutation primitive."
    )]
    async fn account_readiness(
        &self,
        Parameters(params): Parameters<AccountReadinessParams>,
    ) -> Result<CallToolResult, ErrorData> {
        match readiness::scan(&self.api_http, params.provider, params.scope.as_deref()).await {
            Ok(report) => json_result(&report),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "Strict read-only browser fallback for provider consoles using Playwright \
                       or Puppeteer. It performs no clicks or form submissions, aborts every \
                       non-GET/HEAD/OPTIONS request, and blocks top-level navigation outside the \
                       provider/authentication hostname allowlist. Intended for console-only \
                       evidence gaps after API scanning."
    )]
    async fn browser_readiness(
        &self,
        Parameters(params): Parameters<BrowserReadinessParams>,
    ) -> Result<CallToolResult, ErrorData> {
        match readiness::browser_scan(params.provider, params.engine, params.url.as_deref()).await {
            Ok(report) => json_result(&report),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "Return the supported account-readiness provider matrix, credential names, \
                       least-privilege/read-only guidance, check families, and console URLs. \
                       This tool is offline and never touches a customer account."
    )]
    async fn readiness_catalog(&self) -> Result<CallToolResult, ErrorData> {
        json_result(&readiness::catalog())
    }

    #[tool(
        description = "Latest GitHub Actions runs for each canonical-cloud stack repository \
                       (canonical-monorepo, canonical-web-server.rs, canonical-marketing-site.web, \
                       canonical-interfaces). Returns repo, workflow, branch, status, conclusion, \
                       run URL, and timestamp for the five most recent runs per repo."
    )]
    async fn stack_ci_status(
        &self,
        Parameters(params): Parameters<StackCiStatusParams>,
    ) -> Result<CallToolResult, ErrorData> {
        match github::ci_status_report(&self.github, params.repo.as_deref()).await {
            Ok(report) => json_result(&report),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "Compare canonical-monorepo's submodule pins under apps/ against each app \
                       repository's main HEAD. Reports the pinned SHA, main HEAD SHA, whether the \
                       pin is current, and how many commits behind it is."
    )]
    async fn submodule_pins(&self) -> Result<CallToolResult, ErrorData> {
        match github::submodule_pins_report(&self.github).await {
            Ok(report) => json_result(&report),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "Probe a canonical.cloud deployment's health endpoints (/healthz, /readyz, \
                       /api/v1/health) and return status codes and truncated bodies."
    )]
    async fn service_health(
        &self,
        Parameters(params): Parameters<ServiceHealthParams>,
    ) -> Result<CallToolResult, ErrorData> {
        match health::probe(&self.http, &params.base_url).await {
            Ok(reports) => json_result(&reports),
            Err(error) => Err(ErrorData::invalid_params(error, None)),
        }
    }

    #[tool(description = "Fetch canonical.cloud operational docs as markdown. \
                       doc = \"deploy\" (canonical-monorepo docs/deploy.md, fetched live) or \
                       \"repo-boundaries\" (canonical-monorepo docs/repo-boundaries.md, fetched \
                       live) or \"org-map\" (embedded org/infra map: GitOps runtime, shared k8s \
                       libs, dpm migrations, Squarespace/Cloudflare DNS, and fiducia.cloud; \
                       never touches the network).")]
    async fn stack_docs(
        &self,
        Parameters(params): Parameters<StackDocsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        match docs::fetch(&self.http, params.doc).await {
            Ok(markdown) => Ok(CallToolResult::success(vec![ContentBlock::text(markdown)])),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "Read-only fiducia.cloud check: whether canonical.cloud's required \
                       secrets are present and its distributed locks/leases look healthy. \
                       fiducia.cloud is the org's shared secrets (synced with GitHub Actions \
                       secrets) + locks/leases plane. Needs FIDUCIA_URL + FIDUCIA_TOKEN \
                       (optional FIDUCIA_REQUIRED_SECRETS csv). Secret VALUES are never \
                       fetched, only presence; the token is never printed."
    )]
    async fn fiducia_status(&self) -> Result<CallToolResult, ErrorData> {
        let env = match fiducia::env() {
            Ok(env) => env,
            Err(error) => return Ok(tool_error(error)),
        };
        match fiducia::status_report(&self.api_http, &env).await {
            Ok(report) => Ok(CallToolResult::success(vec![ContentBlock::text(report)])),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "Registrar-side and DNS-side status for a domain (default canonical.cloud). \
                       Registrar state (Squarespace has no public domains API) comes from public \
                       RDAP: registrar, status codes, registration/expiration events, delegated \
                       nameservers. Live NS/A/AAAA resolution comes from DNS-over-HTTPS, plus \
                       whether the delegation points at Cloudflare."
    )]
    async fn domain_status(
        &self,
        Parameters(params): Parameters<DomainStatusParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let domain = params.domain.as_deref().unwrap_or(domain::DEFAULT_DOMAIN);
        match domain::domain_status_report(&self.http, domain).await {
            Ok(report) => json_result(&report),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "List DNS records for a Cloudflare zone (default canonical.cloud): type, \
                       name, content, proxied, TTL. Read-only; requires a CLOUDFLARE_API_TOKEN \
                       env var with Zone.Zone:Read and Zone.DNS:Read."
    )]
    async fn cloudflare_dns(
        &self,
        Parameters(params): Parameters<CloudflareDnsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let domain = params.domain.as_deref().unwrap_or(domain::DEFAULT_DOMAIN);
        match cloudflare::dns_records_report(&self.api_http, domain).await {
            Ok(report) => json_result(&report),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(
        description = "Read-only Kubernetes status via `kubectl get` (nodes, pods, deployments, \
                       services, or ingresses), summarized to name/namespace/status/age rows. \
                       Optional namespace and kubeconfig context. Never mutates the cluster."
    )]
    async fn k8s_status(
        &self,
        Parameters(params): Parameters<K8sStatusParams>,
    ) -> Result<CallToolResult, ErrorData> {
        match k8s::k8s_status_report(
            params.resource,
            params.namespace.as_deref(),
            params.context.as_deref(),
        )
        .await
        {
            Ok(report) => json_result(&report),
            Err(error) => Ok(tool_error(error)),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for CanonicalMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "canonical-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Operational and audit tooling for canonical.cloud. Use readiness_catalog for the \
                 twelve-provider least-privilege matrix; account_readiness for strict read-only \
                 account posture scans; and browser_readiness only as a console fallback using \
                 Playwright/Puppeteer with non-read requests blocked. Existing stack tools include \
                 stack_ci_status, submodule_pins, service_health, stack_docs, domain_status, \
                 cloudflare_dns, k8s_status, and fiducia_status. Tokens are never logged or echoed.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_exposes_all_v1_tools() {
        let router = CanonicalMcp::tool_router();
        let names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "account_readiness",
                "browser_readiness",
                "cloudflare_dns",
                "domain_status",
                "fiducia_status",
                "k8s_status",
                "readiness_catalog",
                "service_health",
                "stack_ci_status",
                "stack_docs",
                "submodule_pins",
            ]
        );
    }

    #[test]
    fn stack_docs_schema_restricts_doc_enum() {
        let router = CanonicalMcp::tool_router();
        let tool = router
            .list_all()
            .into_iter()
            .find(|tool| tool.name == "stack_docs")
            .expect("stack_docs registered");
        let schema = serde_json::to_value(&tool.input_schema).expect("schema serializes");
        let text = schema.to_string();
        assert!(text.contains("deploy"), "schema mentions deploy: {text}");
        assert!(
            text.contains("repo-boundaries"),
            "schema mentions repo-boundaries: {text}"
        );
        assert!(text.contains("org-map"), "schema mentions org-map: {text}");
    }

    #[test]
    fn readiness_schema_exposes_provider_and_browser_enums() {
        let router = CanonicalMcp::tool_router();
        let tools = router.list_all();
        let readiness = tools
            .iter()
            .find(|tool| tool.name == "account_readiness")
            .expect("account_readiness registered");
        let readiness_schema = serde_json::to_value(&readiness.input_schema)
            .expect("schema serializes")
            .to_string();
        assert!(readiness_schema.contains("digital-ocean"));
        assert!(readiness_schema.contains("upstash"));

        let browser = tools
            .iter()
            .find(|tool| tool.name == "browser_readiness")
            .expect("browser_readiness registered");
        let browser_schema = serde_json::to_value(&browser.input_schema)
            .expect("schema serializes")
            .to_string();
        assert!(browser_schema.contains("playwright"));
        assert!(browser_schema.contains("puppeteer"));
    }
}
