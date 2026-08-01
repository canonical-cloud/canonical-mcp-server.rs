//! `fiducia_status`: read-only visibility into fiducia.cloud, the org's
//! shared secrets + distributed locks/leases plane (secrets synced with
//! GitHub Actions secrets; fiducia-clients hold fenced leases). This checks
//! secret *presence* and lock/lease *health* only — it never fetches secret
//! values.
//!
//! Env: `FIDUCIA_URL` (base URL) + `FIDUCIA_TOKEN` (read-scoped bearer).
//! Optional `FIDUCIA_REQUIRED_SECRETS` (comma-separated names to assert
//! present; defaults to the credentials this stack itself consumes).

use serde_json::Value;

use super::error_chain;

const DEFAULT_REQUIRED: [&str; 3] = ["DATABASE_URL", "SUPABASE_URL", "CLOUDFLARE_API_TOKEN"];

/// Resolved fiducia.cloud environment: base URL, bearer token, and the
/// secret names to check for presence.
pub struct FiduciaEnv {
    pub url: String,
    pub token: String,
    pub required: Vec<String>,
}

/// Read `FIDUCIA_URL`/`FIDUCIA_TOKEN` (and optional `FIDUCIA_REQUIRED_SECRETS`)
/// from the environment.
pub fn env() -> Result<FiduciaEnv, String> {
    let url = std::env::var("FIDUCIA_URL").map_err(|_| missing_env())?;
    let token = std::env::var("FIDUCIA_TOKEN").map_err(|_| missing_env())?;
    if token.trim().is_empty() || (!url.starts_with("https://") && !url.starts_with("http://")) {
        return Err(missing_env());
    }
    let required = std::env::var("FIDUCIA_REQUIRED_SECRETS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|names| !names.is_empty())
        .unwrap_or_else(|| DEFAULT_REQUIRED.iter().map(|s| s.to_string()).collect());
    Ok(FiduciaEnv {
        url: url.trim_end_matches('/').to_string(),
        token,
        required,
    })
}

fn missing_env() -> String {
    "FIDUCIA_URL and/or FIDUCIA_TOKEN are not set. fiducia.cloud is the org's shared \
     secrets + distributed locks/leases plane; export the base URL (https://…) and a \
     read-scoped bearer token in the environment this MCP server starts in. Optionally \
     set FIDUCIA_REQUIRED_SECRETS (comma-separated) to assert specific secret names. \
     The token is sent only as a bearer header and is never logged or echoed."
        .to_string()
}

async fn get(
    client: &reqwest::Client,
    env: &FiduciaEnv,
    path: &str,
) -> Result<(reqwest::StatusCode, Value), String> {
    let response = client
        .get(format!("{}{path}", env.url))
        .bearer_auth(&env.token)
        .header("accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|error| format!("GET {path} failed: {}", error_chain(&error)))?;
    let status = response.status();
    // Bounded read; a missing/oversized/non-JSON body degrades to Null
    // rather than propagating, matching the tool's tolerant reporting.
    let body: Value = match super::read_body_capped(response, super::MAX_RESPONSE_BYTES).await {
        Ok(text) => serde_json::from_str(&text).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    Ok((status, body))
}

/// Secret *names* present in a fiducia `/v1/secrets` listing; values are
/// never read.
fn secret_names(body: &Value) -> Vec<String> {
    let items = body
        .get("secrets")
        .and_then(Value::as_array)
        .or_else(|| body.as_array());
    let mut names = Vec::new();
    if let Some(list) = items {
        for item in list {
            if let Some(name) = item.as_str() {
                names.push(name.to_string());
            } else if let Some(name) = item.get("name").and_then(Value::as_str) {
                names.push(name.to_string());
            } else if let Some(name) = item.get("key").and_then(Value::as_str) {
                names.push(name.to_string());
            }
        }
    }
    names
}

fn summarize_leases(body: &Value) -> String {
    let leases = body
        .get("leases")
        .and_then(Value::as_array)
        .or_else(|| body.as_array());
    match leases {
        Some(list) if !list.is_empty() => {
            let mut out = format!("{} lease(s):\n", list.len());
            for lease in list.iter().take(50) {
                let name = lease
                    .get("name")
                    .or_else(|| lease.get("key"))
                    .and_then(Value::as_str)
                    .unwrap_or("?");
                let holder = lease.get("holder").and_then(Value::as_str).unwrap_or("-");
                let healthy = lease
                    .get("healthy")
                    .and_then(Value::as_bool)
                    .or_else(|| lease.get("expired").and_then(Value::as_bool).map(|e| !e));
                let state = match healthy {
                    Some(true) => "held",
                    Some(false) => "STALE/EXPIRED",
                    None => "?",
                };
                out.push_str(&format!("  {name}  holder={holder}  {state}\n"));
            }
            out
        }
        _ if body.is_null() => "(no JSON body)\n".to_string(),
        _ => "(no active leases reported)\n".to_string(),
    }
}

/// Bounded, read-only status report: fiducia health, required-secret
/// presence (names only, never values), and lock/lease health.
pub async fn status_report(client: &reqwest::Client, env: &FiduciaEnv) -> Result<String, String> {
    let mut out = format!("fiducia status at {}\n\n", env.url);

    let (health_status, health_body) = get(client, env, "/health").await?;
    out.push_str(&format!("## /health — HTTP {health_status}\n"));
    match health_body.get("status").and_then(Value::as_str) {
        Some(status) => out.push_str(&format!("  status: {status}\n")),
        None if health_body.is_null() => out.push_str("  (no JSON body)\n"),
        None => {}
    }

    let (secrets_status, secrets_body) = get(client, env, "/v1/secrets").await?;
    out.push_str(&format!(
        "\n## required secrets ({} checked)\n",
        env.required.len()
    ));
    if secrets_status.is_success() {
        let present = secret_names(&secrets_body);
        for name in &env.required {
            let ok = present.iter().any(|n| n == name);
            out.push_str(&format!(
                "  {name}: {}\n",
                if ok { "present" } else { "MISSING" }
            ));
        }
    } else {
        out.push_str(&format!(
            "  could not list secrets (HTTP {secrets_status}); token may lack read scope\n"
        ));
    }

    let (leases_status, leases_body) = get(client, env, "/v1/leases").await?;
    out.push_str(&format!("\n## locks/leases — HTTP {leases_status}\n"));
    out.push_str(&summarize_leases(&leases_body));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_env_is_actionable_and_leakfree() {
        let message = missing_env();
        assert!(message.contains("FIDUCIA_URL"));
        assert!(message.contains("FIDUCIA_TOKEN"));
        assert!(message.contains("never logged"));
    }

    #[test]
    fn secret_names_handles_shapes() {
        assert_eq!(
            secret_names(&json!({"secrets": ["A", "B"]})),
            vec!["A", "B"]
        );
        assert_eq!(
            secret_names(&json!([{"name": "X"}, {"key": "Y"}])),
            vec!["X", "Y"]
        );
        assert!(secret_names(&Value::Null).is_empty());
    }

    #[test]
    fn summarize_leases_flags_expired_and_empty() {
        let summary = summarize_leases(&json!({"leases": [
            {"name": "canonical:release", "holder": "ci-9", "healthy": true},
            {"name": "stale", "holder": "runner-1", "expired": true}
        ]}));
        assert!(summary.contains("canonical:release"));
        assert!(summary.contains("held"));
        assert!(summary.contains("STALE/EXPIRED"));
        assert!(summarize_leases(&json!({"leases": []})).contains("no active leases"));
        assert!(summarize_leases(&Value::Null).contains("no JSON body"));
    }
}
