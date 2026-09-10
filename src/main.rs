//! canonical-mcp: an MCP server for operating the canonical.cloud stack.
//!
//! Serves over stdio. `main` is bootstrap only; the tools live in
//! [`server`] and [`tools`].

mod env_map;
mod flags;
mod server;
mod telemetry;
mod tools;

use rmcp::{transport::stdio, ServiceExt};
use tracing::Instrument;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = flags::apply_cli_flags()?;
    let _telemetry = telemetry::init("canonical-mcp-server", "canonical-cloud", &env);
    tracing::info!(transport = "stdio", "starting MCP server");
    let server_span = tracing::info_span!("mcp.server", rpc.system = "mcp", transport = "stdio");
    let service = server::CanonicalMcp::new()?
        .serve(stdio())
        .instrument(server_span.clone())
        .await?;
    service.waiting().instrument(server_span).await?;
    Ok(())
}
