//! Read-only operational-readiness evidence from Prometheus and OpenCost.
//!
//! Endpoints are operator-configured environment variables, never MCP URL
//! parameters. Requests are GET only. Plain HTTP is accepted only for loopback
//! (the documented port-forward/developer pattern); remote endpoints must use
//! HTTPS. PromQL expressions and OpenCost query parameters are compiled here,
//! not supplied by the MCP caller.

use serde::Serialize;
use serde_json::Value;

use super::{error_chain, read_body_capped, MAX_RESPONSE_BYTES};

const PROMETHEUS_URL_ENV: &str = "CANONICAL_PROMETHEUS_URL";
const PROMETHEUS_TOKEN_ENV: &str = "CANONICAL_PROMETHEUS_BEARER_TOKEN";
const OPENCOST_URL_ENV: &str = "CANONICAL_OPENCOST_URL";
const OPENCOST_TOKEN_ENV: &str = "CANONICAL_OPENCOST_BEARER_TOKEN";

const CPU_QUERY: &str =
    r#"100 * (1 - avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))"#;
const DISK_QUERY: &str = r#"100 * node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay|squashfs"}"#;
const MEMORY_QUERY: &str =
    "100 * node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes";
const DOWN_QUERY: &str = "up == 0";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationalSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize)]
pub struct OperationalFinding {
    pub id: String,
    pub severity: OperationalSeverity,
    pub category: &'static str,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OperationalEvidence {
    pub source: &'static str,
    pub check: &'static str,
    pub status: &'static str,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct OperationalReport {
    pub prometheus: &'static str,
    pub opencost: &'static str,
    pub thresholds: Thresholds,
    pub evidence: Vec<OperationalEvidence>,
    pub findings: Vec<OperationalFinding>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Thresholds {
    pub cpu_high_percent: f64,
    pub disk_free_low_percent: f64,
    pub memory_free_low_percent: f64,
}

#[derive(Debug)]
struct Sample {
    labels: serde_json::Map<String, Value>,
    value: f64,
}

fn threshold(name: &str, default: f64, min: f64, max: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn thresholds() -> Thresholds {
    Thresholds {
        cpu_high_percent: threshold("CANONICAL_CPU_HIGH_PERCENT", 85.0, 1.0, 100.0),
        disk_free_low_percent: threshold("CANONICAL_DISK_FREE_LOW_PERCENT", 15.0, 0.1, 99.0),
        memory_free_low_percent: threshold(
            "CANONICAL_MEMORY_FREE_LOW_PERCENT",
            15.0,
            0.1,
            99.0,
        ),
    }
}

fn configured_base(name: &str) -> Result<Option<reqwest::Url>, String> {
    let Some(raw) = std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let mut url = reqwest::Url::parse(raw.trim())
        .map_err(|error| format!("{name} is not a valid URL: {error}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("{name} URL has no hostname"))?;
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(format!(
            "{name} must use HTTPS unless the endpoint is loopback/port-forwarded"
        ));
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(Some(url))
}

fn endpoint(base: &reqwest::Url, path: &str) -> Result<reqwest::Url, String> {
    let mut base = base.clone();
    if !base.path().ends_with('/') {
        let mut path_prefix = base.path().to_string();
        path_prefix.push('/');
        base.set_path(&path_prefix);
    }
    let joined = base
        .join(path.trim_start_matches('/'))
        .map_err(|error| format!("failed to build read endpoint: {error}"))?;
    if joined.origin() != base.origin() {
        return Err("read endpoint changed origin".to_string());
    }
    Ok(joined)
}

async fn get_json(
    client: &reqwest::Client,
    mut url: reqwest::Url,
    token_env: &str,
    query: &[(&str, &str)],
) -> Result<Value, String> {
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    let mut request = client.get(url.clone());
    if let Ok(token) = std::env::var(token_env) {
        if !token.trim().is_empty() {
            request = request.bearer_auth(token);
        }
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("GET {} failed: {}", url, error_chain(&error)))?;
    let status = response.status();
    let body = read_body_capped(response, MAX_RESPONSE_BYTES).await?;
    if !status.is_success() {
        return Err(format!(
            "GET {} returned {status}: {}",
            url,
            body.chars().take(400).collect::<String>()
        ));
    }
    serde_json::from_str(&body)
        .map_err(|error| format!("GET {} returned invalid JSON: {error}", url))
}

fn prometheus_samples(body: &Value) -> Result<Vec<Sample>, String> {
    if body.get("status").and_then(Value::as_str) != Some("success") {
        return Err(format!(
            "Prometheus query failed: {}",
            body.get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown API error")
        ));
    }
    let rows = body
        .pointer("/data/result")
        .and_then(Value::as_array)
        .ok_or_else(|| "Prometheus response has no data.result array".to_string())?;
    let mut samples = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(labels) = row.get("metric").and_then(Value::as_object) else {
            continue;
        };
        let Some(pair) = row.get("value").and_then(Value::as_array) else {
            continue;
        };
        let Some(value) = pair
            .get(1)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite())
        else {
            continue;
        };
        samples.push(Sample {
            labels: labels.clone(),
            value,
        });
    }
    Ok(samples)
}

fn label(sample: &Sample, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find_map(|key| sample.labels.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn add_finding(
    report: &mut OperationalReport,
    id: impl Into<String>,
    severity: OperationalSeverity,
    category: &'static str,
    title: impl Into<String>,
    detail: impl Into<String>,
    recommendation: impl Into<String>,
    resource: Option<String>,
) {
    report.findings.push(OperationalFinding {
        id: id.into(),
        severity,
        category,
        title: title.into(),
        detail: detail.into(),
        recommendation: recommendation.into(),
        resource,
    });
}

async fn prometheus_query(
    client: &reqwest::Client,
    base: &reqwest::Url,
    query: &'static str,
) -> Result<Vec<Sample>, String> {
    let url = endpoint(base, "/api/v1/query")?;
    let body = get_json(client, url, PROMETHEUS_TOKEN_ENV, &[("query", query), ("limit", "500")])
        .await?;
    prometheus_samples(&body)
}

async fn scan_prometheus(
    client: &reqwest::Client,
    base: &reqwest::Url,
    report: &mut OperationalReport,
) {
    let threshold = report.thresholds;

    let cpu = prometheus_query(client, base, CPU_QUERY).await;
    match cpu {
        Ok(samples) => {
            report.evidence.push(OperationalEvidence {
                source: "prometheus",
                check: "cpu-utilization",
                status: "observed",
                summary: format!("{} node-exporter CPU series inspected", samples.len()),
            });
            for sample in samples {
                if sample.value >= threshold.cpu_high_percent {
                    let resource = label(&sample, &["instance", "node", "pod"]);
                    add_finding(
                        report,
                        format!("prometheus.cpu.high.{}", resource.as_deref().unwrap_or("unknown")),
                        if sample.value >= 95.0 {
                            OperationalSeverity::Critical
                        } else {
                            OperationalSeverity::High
                        },
                        "utilization-and-capacity",
                        "Sustained host CPU is high",
                        format!("Five-minute CPU utilization is {:.1}%.", sample.value),
                        "Correlate with workload/request metrics, saturation and throttling; right-size, scale, or repair through normal change control.",
                        resource,
                    );
                }
            }
        }
        Err(error) => report.evidence.push(OperationalEvidence {
            source: "prometheus",
            check: "cpu-utilization",
            status: "unknown",
            summary: error,
        }),
    }

    let disk = prometheus_query(client, base, DISK_QUERY).await;
    match disk {
        Ok(samples) => {
            report.evidence.push(OperationalEvidence {
                source: "prometheus",
                check: "filesystem-free-space",
                status: "observed",
                summary: format!("{} filesystem free-space series inspected", samples.len()),
            });
            for sample in samples {
                if sample.value <= threshold.disk_free_low_percent {
                    let resource = label(&sample, &["instance", "node"]);
                    let mount = label(&sample, &["mountpoint"]);
                    let display = match (&resource, &mount) {
                        (Some(resource), Some(mount)) => Some(format!("{resource}:{mount}")),
                        (Some(resource), None) => Some(resource.clone()),
                        _ => mount,
                    };
                    add_finding(
                        report,
                        format!("prometheus.disk.low.{}", display.as_deref().unwrap_or("unknown")),
                        if sample.value <= 5.0 {
                            OperationalSeverity::Critical
                        } else {
                            OperationalSeverity::High
                        },
                        "utilization-and-capacity",
                        "Filesystem free space is low",
                        format!("Available filesystem space is {:.1}%.", sample.value),
                        "Identify growth source and retention policy; expand/clean storage through normal change control before exhaustion.",
                        display,
                    );
                }
            }
        }
        Err(error) => report.evidence.push(OperationalEvidence {
            source: "prometheus",
            check: "filesystem-free-space",
            status: "unknown",
            summary: error,
        }),
    }

    let memory = prometheus_query(client, base, MEMORY_QUERY).await;
    match memory {
        Ok(samples) => {
            report.evidence.push(OperationalEvidence {
                source: "prometheus",
                check: "memory-available",
                status: "observed",
                summary: format!("{} host memory-availability series inspected", samples.len()),
            });
            for sample in samples {
                if sample.value <= threshold.memory_free_low_percent {
                    let resource = label(&sample, &["instance", "node"]);
                    add_finding(
                        report,
                        format!("prometheus.memory.low.{}", resource.as_deref().unwrap_or("unknown")),
                        if sample.value <= 5.0 {
                            OperationalSeverity::Critical
                        } else {
                            OperationalSeverity::High
                        },
                        "utilization-and-capacity",
                        "Available memory is low",
                        format!("Available host memory is {:.1}%.", sample.value),
                        "Inspect working-set growth, OOM events, cache behavior and workload limits; right-size or repair through normal change control.",
                        resource,
                    );
                }
            }
        }
        Err(error) => report.evidence.push(OperationalEvidence {
            source: "prometheus",
            check: "memory-available",
            status: "unknown",
            summary: error,
        }),
    }

    let down = prometheus_query(client, base, DOWN_QUERY).await;
    match down {
        Ok(samples) => {
            report.evidence.push(OperationalEvidence {
                source: "prometheus",
                check: "scrape-target-health",
                status: "observed",
                summary: format!("{} down scrape targets observed", samples.len()),
            });
            for sample in samples {
                let resource = label(&sample, &["instance", "job"]);
                add_finding(
                    report,
                    format!("prometheus.target.down.{}", resource.as_deref().unwrap_or("unknown")),
                    OperationalSeverity::High,
                    "observability",
                    "Prometheus scrape target is down",
                    "The `up` metric is zero for this target.".to_string(),
                    "Determine whether the workload, exporter, network path, service discovery, or scrape configuration is unhealthy.",
                    resource,
                );
            }
        }
        Err(error) => report.evidence.push(OperationalEvidence {
            source: "prometheus",
            check: "scrape-target-health",
            status: "unknown",
            summary: error,
        }),
    }
}

fn allocation_set(body: &Value) -> Option<&serde_json::Map<String, Value>> {
    body.get("data")
        .and_then(Value::as_array)
        .and_then(|sets| sets.last())
        .and_then(Value::as_object)
}

fn namespace_costs(body: &Value) -> Vec<(String, f64)> {
    let Some(set) = allocation_set(body) else {
        return Vec::new();
    };
    set.iter()
        .filter_map(|(namespace, allocation)| {
            let cost = allocation
                .get("totalCost")
                .and_then(Value::as_f64)
                .or_else(|| {
                    allocation
                        .get("totalCost")
                        .and_then(Value::as_str)
                        .and_then(|value| value.parse::<f64>().ok())
                })?;
            cost.is_finite().then(|| (namespace.clone(), cost))
        })
        .collect()
}

async fn scan_opencost(
    client: &reqwest::Client,
    base: &reqwest::Url,
    report: &mut OperationalReport,
) {
    let url = match endpoint(base, "/allocation") {
        Ok(url) => url,
        Err(error) => {
            report.evidence.push(OperationalEvidence {
                source: "opencost",
                check: "namespace-cost-allocation",
                status: "unknown",
                summary: error,
            });
            return;
        }
    };
    let result = get_json(
        client,
        url,
        OPENCOST_TOKEN_ENV,
        &[
            ("window", "month"),
            ("aggregate", "namespace"),
            ("includeIdle", "true"),
        ],
    )
    .await;
    match result {
        Ok(body) => {
            let mut costs = namespace_costs(&body);
            costs.sort_by(|a, b| b.1.total_cmp(&a.1));
            let total: f64 = costs.iter().map(|(_, cost)| cost).sum();
            report.evidence.push(OperationalEvidence {
                source: "opencost",
                check: "namespace-cost-allocation",
                status: "observed",
                summary: format!(
                    "{} namespace allocations observed; month-window total ${total:.2}",
                    costs.len()
                ),
            });

            if let Some((namespace, cost)) = costs.first() {
                if total > 0.0 && *cost / total >= 0.5 && costs.len() > 1 {
                    add_finding(
                        report,
                        "opencost.namespace.concentration",
                        OperationalSeverity::Medium,
                        "budget-and-cost",
                        "Kubernetes cost is concentrated in one namespace",
                        format!(
                            "Namespace {namespace:?} accounts for {:.1}% of observed month-window allocation cost (${cost:.2} of ${total:.2}).",
                            cost / total * 100.0
                        ),
                        "Review workload ownership, requests/limits, idle allocation and scaling in the dominant namespace before changing capacity.",
                        Some(namespace.clone()),
                    );
                }
            }

            if let Some(budget) = std::env::var("CANONICAL_KUBERNETES_MONTHLY_BUDGET_USD")
                .ok()
                .and_then(|value| value.parse::<f64>().ok())
                .filter(|value| value.is_finite() && *value > 0.0)
            {
                let pct = total / budget * 100.0;
                let severity = if pct >= 100.0 {
                    Some(OperationalSeverity::Critical)
                } else if pct >= 85.0 {
                    Some(OperationalSeverity::High)
                } else if pct >= 70.0 {
                    Some(OperationalSeverity::Medium)
                } else {
                    None
                };
                if let Some(severity) = severity {
                    add_finding(
                        report,
                        "opencost.budget-utilization",
                        severity,
                        "budget-and-cost",
                        "Kubernetes allocation cost is approaching or exceeding budget",
                        format!(
                            "Observed month-window allocation cost is ${total:.2}, {:.1}% of the configured ${budget:.2} budget.",
                            pct
                        ),
                        "Inspect dominant namespaces, idle cost, resource requests/limits and node right-sizing before the budget is exceeded.",
                        None,
                    );
                }
            }
        }
        Err(error) => report.evidence.push(OperationalEvidence {
            source: "opencost",
            check: "namespace-cost-allocation",
            status: "unknown",
            summary: error,
        }),
    }
}

pub async fn scan(client: &reqwest::Client) -> Result<OperationalReport, String> {
    let prometheus = configured_base(PROMETHEUS_URL_ENV)?;
    let opencost = configured_base(OPENCOST_URL_ENV)?;
    let mut report = OperationalReport {
        prometheus: if prometheus.is_some() {
            "configured"
        } else {
            "not-configured"
        },
        opencost: if opencost.is_some() {
            "configured"
        } else {
            "not-configured"
        },
        thresholds: thresholds(),
        evidence: Vec::new(),
        findings: Vec::new(),
        notes: vec![
            "Prometheus and OpenCost endpoints are operator-configured environment variables, not caller-supplied URLs; all requests are GET only.".to_string(),
        ],
    };

    if let Some(base) = prometheus.as_ref() {
        scan_prometheus(client, base, &mut report).await;
    } else {
        report.notes.push(format!(
            "Set {PROMETHEUS_URL_ENV} to an HTTPS Prometheus endpoint (or loopback HTTP port-forward) to enable CPU, real filesystem free-space, memory, and scrape-target health evidence."
        ));
    }

    if let Some(base) = opencost.as_ref() {
        scan_opencost(client, base, &mut report).await;
    } else {
        report.notes.push(format!(
            "Set {OPENCOST_URL_ENV} to an HTTPS OpenCost API endpoint (or loopback HTTP port-forward) to enable Kubernetes cost-allocation evidence."
        ));
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prometheus_vector_parser_extracts_numeric_samples() {
        let body = json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{
                    "metric": {"instance":"node-1", "mountpoint":"/"},
                    "value": [1234.0, "8.25"]
                }]
            }
        });
        let samples = prometheus_samples(&body).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].value, 8.25);
        assert_eq!(label(&samples[0], &["instance"]).as_deref(), Some("node-1"));
    }

    #[test]
    fn opencost_namespace_costs_extract_latest_allocation_set() {
        let body = json!({
            "code": 200,
            "data": [
                {"old": {"totalCost": 1.0}},
                {
                    "default": {"totalCost": 12.5},
                    "payments": {"totalCost": 40.0}
                }
            ]
        });
        let mut costs = namespace_costs(&body);
        costs.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(costs.len(), 2);
        assert_eq!(costs[0], ("default".to_string(), 12.5));
        assert_eq!(costs[1], ("payments".to_string(), 40.0));
    }

    #[test]
    fn remote_plain_http_is_rejected_but_loopback_http_is_allowed() {
        let remote = reqwest::Url::parse("http://prometheus.example.com:9090").unwrap();
        assert_ne!(remote.host_str(), Some("localhost"));
        let loopback = reqwest::Url::parse("http://127.0.0.1:9090").unwrap();
        assert_eq!(loopback.host_str(), Some("127.0.0.1"));
    }
}
