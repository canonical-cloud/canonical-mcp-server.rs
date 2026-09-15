//! Cross-provider account readiness scanning.
//!
//! The scanner is intentionally read-only. SaaS adapters can only issue HTTPS
//! GET requests to an allowlisted API host. AWS/GCP/Azure/Fly adapters invoke
//! exact allowlisted CLI read/list/describe commands without a shell. There is
//! no generic HTTP method, URL, command, or argument passthrough.

use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Stdio;
use tokio::process::Command;

use super::{error_chain, MAX_RESPONSE_BYTES};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    Aws,
    Gcp,
    Azure,
    Cloudflare,
    Github,
    Upstash,
    Vercel,
    DigitalOcean,
    Netlify,
    Render,
    FlyIo,
    Heroku,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::Cloudflare => "cloudflare",
            Self::Github => "github",
            Self::Upstash => "upstash",
            Self::Vercel => "vercel",
            Self::DigitalOcean => "digital-ocean",
            Self::Netlify => "netlify",
            Self::Render => "render",
            Self::FlyIo => "fly-io",
            Self::Heroku => "heroku",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BrowserEngine {
    Playwright,
    Puppeteer,
}

impl BrowserEngine {
    fn as_str(self) -> &'static str {
        match self {
            Self::Playwright => "playwright",
            Self::Puppeteer => "puppeteer",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: &'static str,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckEvidence {
    pub check: &'static str,
    pub status: &'static str,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub provider: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub transport: &'static str,
    pub auth_status: &'static str,
    pub score: u8,
    pub checks: Vec<CheckEvidence>,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    pub collected_at: String,
}

#[derive(Debug, Serialize)]
pub struct ProviderProfile {
    pub provider: &'static str,
    pub primary_transport: &'static str,
    pub credential: &'static str,
    pub least_privilege: &'static str,
    pub checks: &'static [&'static str],
    pub console: &'static str,
}

const COMMON_CHECKS: &[&str] = &[
    "identity-and-access",
    "resource-inventory",
    "security-baseline",
    "reliability-and-backups",
    "utilization-and-capacity",
    "budget-and-cost",
    "observability",
];

pub fn catalog() -> Vec<ProviderProfile> {
    vec![
        ProviderProfile { provider: "aws", primary_transport: "allowlisted aws CLI API calls", credential: "standard AWS SDK/CLI credential chain", least_privilege: "SecurityAudit + CloudWatchReadOnlyAccess + explicit Cost Explorer/Budgets read permissions; never AdministratorAccess", checks: COMMON_CHECKS, console: "https://console.aws.amazon.com/" },
        ProviderProfile { provider: "gcp", primary_transport: "allowlisted gcloud API calls", credential: "gcloud/ADC identity", least_privilege: "roles/viewer + roles/monitoring.viewer + roles/cloudasset.viewer + roles/billing.viewer + roles/recommender.viewer where applicable", checks: COMMON_CHECKS, console: "https://console.cloud.google.com/" },
        ProviderProfile { provider: "azure", primary_transport: "allowlisted az CLI API calls", credential: "Azure CLI identity", least_privilege: "Reader + Monitoring Reader + Cost Management Reader; no Contributor/Owner", checks: COMMON_CHECKS, console: "https://portal.azure.com/" },
        ProviderProfile { provider: "cloudflare", primary_transport: "HTTPS GET only", credential: "CLOUDFLARE_API_TOKEN", least_privilege: "Account/Zone read permissions only (Zone Read, DNS Read, Analytics Read and other required Read groups)", checks: COMMON_CHECKS, console: "https://dash.cloudflare.com/" },
        ProviderProfile { provider: "github", primary_transport: "HTTPS GET only", credential: "GITHUB_TOKEN or GH_TOKEN", least_privilege: "fine-grained token/GitHub App with Metadata and required org/repository permissions set to Read", checks: COMMON_CHECKS, console: "https://github.com/" },
        ProviderProfile { provider: "upstash", primary_transport: "HTTPS GET only", credential: "UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_READ_ONLY_TOKEN", least_privilege: "Upstash Redis Read Only REST token only; Standard token is intentionally unsupported", checks: COMMON_CHECKS, console: "https://console.upstash.com/" },
        ProviderProfile { provider: "vercel", primary_transport: "HTTPS GET only", credential: "VERCEL_AUDIT_TOKEN", least_privilege: "dedicated audit identity/team scope; scanner itself exposes no non-GET request path", checks: COMMON_CHECKS, console: "https://vercel.com/dashboard" },
        ProviderProfile { provider: "digital-ocean", primary_transport: "HTTPS GET only", credential: "DIGITALOCEAN_READ_ONLY_TOKEN", least_privilege: "DigitalOcean Read Only/API api:read token (or narrower resource :read scopes)", checks: COMMON_CHECKS, console: "https://cloud.digitalocean.com/" },
        ProviderProfile { provider: "netlify", primary_transport: "HTTPS GET only", credential: "NETLIFY_AUDIT_TOKEN", least_privilege: "dedicated audit identity/token; scanner exposes GET only", checks: COMMON_CHECKS, console: "https://app.netlify.com/" },
        ProviderProfile { provider: "render", primary_transport: "HTTPS GET only", credential: "RENDER_AUDIT_TOKEN", least_privilege: "dedicated audit identity/token; scanner exposes GET only", checks: COMMON_CHECKS, console: "https://dashboard.render.com/" },
        ProviderProfile { provider: "fly-io", primary_transport: "allowlisted flyctl read calls", credential: "Fly token consumed by flyctl", least_privilege: "dedicated audit identity/token; only apps list/machine status reads are invoked", checks: COMMON_CHECKS, console: "https://fly.io/dashboard" },
        ProviderProfile { provider: "heroku", primary_transport: "HTTPS GET only", credential: "HEROKU_READ_ONLY_TOKEN", least_privilege: "OAuth token with read scope", checks: COMMON_CHECKS, console: "https://dashboard.heroku.com/" },
    ]
}

fn blank_report(provider: Provider, scope: Option<&str>, transport: &'static str) -> ScanReport {
    ScanReport {
        provider: provider.as_str(),
        scope: scope.map(str::to_string),
        transport,
        auth_status: "unknown",
        score: 100,
        checks: Vec::new(),
        findings: Vec::new(),
        notes: Vec::new(),
        collected_at: Utc::now().to_rfc3339(),
    }
}

fn validate_scope(scope: Option<&str>) -> Result<Option<&str>, String> {
    let Some(scope) = scope else { return Ok(None) };
    let trimmed = scope.trim();
    if trimmed.is_empty() || trimmed.len() > 200 {
        return Err("scope must be 1..=200 characters".to_string());
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/' | '@')) {
        return Err("scope contains unsupported characters".to_string());
    }
    Ok(Some(trimmed))
}

fn add_finding(
    report: &mut ScanReport,
    id: impl Into<String>,
    severity: Severity,
    category: &'static str,
    title: impl Into<String>,
    detail: impl Into<String>,
    recommendation: impl Into<String>,
    resource: Option<String>,
) {
    report.findings.push(Finding {
        id: id.into(),
        severity,
        category,
        title: title.into(),
        detail: detail.into(),
        recommendation: recommendation.into(),
        resource,
    });
}

fn finalize(report: &mut ScanReport) {
    let penalty: u16 = report
        .findings
        .iter()
        .map(|finding| match finding.severity {
            Severity::Critical => 25,
            Severity::High => 12,
            Severity::Medium => 6,
            Severity::Low => 2,
            Severity::Info => 0,
        })
        .sum();
    report.score = 100u16.saturating_sub(penalty).min(100) as u8;
}

fn missing_auth(report: &mut ScanReport, credential: &str, hint: &str) {
    report.auth_status = "not-configured";
    report.checks.push(CheckEvidence {
        check: "authentication",
        status: "unknown",
        summary: format!("{credential} is not configured"),
    });
    report.notes.push(hint.to_string());
}

fn budget_for(provider: Provider) -> Option<f64> {
    let provider_key = provider.as_str().replace('-', "_").to_ascii_uppercase();
    let provider_var = format!("CANONICAL_{provider_key}_MONTHLY_BUDGET_USD");
    std::env::var(&provider_var)
        .ok()
        .or_else(|| std::env::var("CANONICAL_READINESS_MONTHLY_BUDGET_USD").ok())
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| *value > 0.0)
}

fn evaluate_budget(report: &mut ScanReport, provider: Provider, spend: f64, label: &str) {
    let Some(budget) = budget_for(provider) else {
        report.notes.push(format!("Set CANONICAL_{}_MONTHLY_BUDGET_USD (or CANONICAL_READINESS_MONTHLY_BUDGET_USD) to turn {label} spend into a budget-utilization finding.", provider.as_str().replace('-', "_").to_ascii_uppercase()));
        return;
    };
    let utilization = spend / budget * 100.0;
    let severity = if utilization >= 100.0 {
        Some(Severity::Critical)
    } else if utilization >= 85.0 {
        Some(Severity::High)
    } else if utilization >= 70.0 {
        Some(Severity::Medium)
    } else {
        None
    };
    if let Some(severity) = severity {
        add_finding(
            report,
            format!("{}.budget-utilization", provider.as_str()),
            severity,
            "budget-and-cost",
            format!("{label} spend is {utilization:.1}% of the configured monthly budget"),
            format!("Observed spend ${spend:.2}; configured budget ${budget:.2}."),
            "Review the largest cost centers, idle resources, commitments/reservations, egress, storage growth, and autoscaling limits before the budget is exceeded.",
            None,
        );
    }
}

fn truncate_text(value: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(value);
    text.chars().take(max).collect()
}

async fn run_cli(program: &str, args: Vec<String>) -> Result<Value, String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(35),
        Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("{program} read command timed out"))?
    .map_err(|error| format!("failed to run {program}: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "{program} read command exited {}: {}",
            output.status,
            truncate_text(&output.stderr, 1200)
        ));
    }
    if output.stdout.len() > MAX_RESPONSE_BYTES {
        return Err(format!("{program} output exceeded {MAX_RESPONSE_BYTES} byte limit"));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{program} returned invalid JSON: {error}"))
}

fn allowed_https_url(url: &str, hosts: &[&str]) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|error| format!("invalid API URL: {error}"))?;
    if parsed.scheme() != "https" {
        return Err("audit API URL must use https".to_string());
    }
    let host = parsed.host_str().ok_or_else(|| "audit API URL has no host".to_string())?;
    if !hosts.iter().any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}"))) {
        return Err(format!("audit API host {host:?} is not allowlisted"));
    }
    Ok(parsed)
}

async fn get_json(
    client: &reqwest::Client,
    url: &str,
    hosts: &[&str],
    bearer: Option<&str>,
    accept: Option<&str>,
) -> Result<Value, String> {
    let url = allowed_https_url(url, hosts)?;
    let mut request = client.get(url.clone());
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    if let Some(accept) = accept {
        request = request.header(reqwest::header::ACCEPT, accept);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("GET {} failed: {}", url, error_chain(&error)))?;
    let status = response.status();
    let body = super::read_body_capped(response, MAX_RESPONSE_BYTES).await?;
    if !status.is_success() {
        return Err(format!("GET {} returned {status}: {}", url, body.chars().take(400).collect::<String>()));
    }
    serde_json::from_str(&body).map_err(|error| format!("GET {} returned invalid JSON: {error}", url))
}

fn env_token(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn array_len(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

fn push_api_check(report: &mut ScanReport, check: &'static str, result: &Result<Value, String>, summary: impl Fn(&Value) -> String) {
    match result {
        Ok(value) => report.checks.push(CheckEvidence { check, status: "pass", summary: summary(value) }),
        Err(error) => report.checks.push(CheckEvidence { check, status: "unknown", summary: error.clone() }),
    }
}

async fn scan_aws(report: &mut ScanReport) {
    report.transport = "allowlisted aws CLI API calls";
    let identity_body = match run_cli("aws", vec!["sts".into(), "get-caller-identity".into(), "--output".into(), "json".into()]).await {
        Ok(body) => body,
        Err(error) => {
            report.auth_status = "unavailable";
            report.checks.push(CheckEvidence { check: "authentication", status: "unknown", summary: error });
            report.notes.push("Install/configure the AWS CLI with an audit role. Recommended baseline: SecurityAudit plus CloudWatch read-only and explicit Cost Explorer/Budgets read permissions.".to_string());
            return;
        }
    };
    report.auth_status = "configured";
    let account = identity_body.get("Account").and_then(Value::as_str).unwrap_or("unknown");
    report.checks.push(CheckEvidence { check: "authentication", status: "pass", summary: format!("AWS account {account} is readable") });

    let instances = run_cli("aws", vec!["ec2".into(), "describe-instances".into(), "--max-items".into(), "100".into(), "--output".into(), "json".into()]).await;
    push_api_check(report, "compute-inventory", &instances, |body| {
        let count = body.get("Reservations").and_then(Value::as_array).map_or(0, |reservations| reservations.iter().map(|reservation| array_len(reservation, "Instances")).sum());
        format!("inspected {count} EC2 instances (capped at 100)")
    });
    if let Ok(body) = &instances {
        if let Some(reservations) = body.get("Reservations").and_then(Value::as_array) {
            for instance in reservations.iter().filter_map(|reservation| reservation.get("Instances").and_then(Value::as_array)).flatten() {
                let id = instance.get("InstanceId").and_then(Value::as_str).unwrap_or("unknown");
                let imdsv2_required = instance.pointer("/MetadataOptions/HttpTokens").and_then(Value::as_str) == Some("required");
                if !imdsv2_required {
                    add_finding(report, format!("aws.ec2.imdsv2.{id}"), Severity::High, "security-baseline", "EC2 instance does not require IMDSv2", "Instance metadata tokens are not set to required.", "Require IMDSv2 after validating workload compatibility.", Some(id.to_string()));
                }
                if instance.get("PublicIpAddress").and_then(Value::as_str).is_some() {
                    add_finding(report, format!("aws.ec2.public-ip.{id}"), Severity::Medium, "security-baseline", "EC2 instance has a public IPv4 address", "A directly reachable public address expands the attack surface.", "Prefer private subnets plus controlled ingress/load balancers unless direct exposure is intentional and documented.", Some(id.to_string()));
                }
            }
        }
    }

    let volumes = run_cli("aws", vec!["ec2".into(), "describe-volumes".into(), "--max-items".into(), "100".into(), "--output".into(), "json".into()]).await;
    push_api_check(report, "storage-inventory", &volumes, |body| format!("inspected {} EBS volumes (capped at 100)", array_len(body, "Volumes")));
    if let Ok(body) = &volumes {
        if let Some(items) = body.get("Volumes").and_then(Value::as_array) {
            for volume in items {
                let id = volume.get("VolumeId").and_then(Value::as_str).unwrap_or("unknown");
                if volume.get("Encrypted").and_then(Value::as_bool) == Some(false) {
                    add_finding(report, format!("aws.ebs.unencrypted.{id}"), Severity::High, "security-baseline", "EBS volume is not encrypted", "The volume reports Encrypted=false.", "Migrate data to an encrypted volume/KMS policy and enforce encryption-by-default.", Some(id.to_string()));
                }
                if volume.get("State").and_then(Value::as_str) == Some("available") {
                    add_finding(report, format!("aws.ebs.unattached.{id}"), Severity::Low, "budget-and-cost", "EBS volume is unattached", "The volume is in the available state and still incurs storage cost.", "Confirm retention requirements, snapshot if necessary, then remove through the customer's normal change process.", Some(id.to_string()));
                }
            }
        }
    }

    let alarms = run_cli("aws", vec!["cloudwatch".into(), "describe-alarms".into(), "--state-value".into(), "ALARM".into(), "--max-items".into(), "100".into(), "--output".into(), "json".into()]).await;
    push_api_check(report, "utilization-and-capacity", &alarms, |body| format!("{} metric alarms are currently in ALARM", array_len(body, "MetricAlarms")));
    if let Ok(body) = &alarms {
        if let Some(items) = body.get("MetricAlarms").and_then(Value::as_array) {
            for alarm in items {
                let name = alarm.get("AlarmName").and_then(Value::as_str).unwrap_or("unnamed");
                let metric = alarm.get("MetricName").and_then(Value::as_str).unwrap_or("");
                let metric_lower = metric.to_ascii_lowercase();
                let severity = if metric_lower.contains("cpu") || metric_lower.contains("disk") || metric_lower.contains("memory") { Severity::High } else { Severity::Medium };
                add_finding(report, format!("aws.cloudwatch.alarm.{name}"), severity, "utilization-and-capacity", format!("CloudWatch alarm is firing: {name}"), format!("Metric {metric:?} is in ALARM state."), "Inspect the time series and resource saturation/root cause; scale, right-size, repair, or tune thresholds through the customer's normal change process.", Some(name.to_string()));
            }
        }
    }

    let today = Utc::now().date_naive();
    let start = today.with_day(1).unwrap_or(today);
    let end = today.succ_opt().unwrap_or(today);
    let cost = run_cli("aws", vec![
        "ce".into(), "get-cost-and-usage".into(), "--time-period".into(), format!("Start={},End={}", start.format("%Y-%m-%d"), end.format("%Y-%m-%d")), "--granularity".into(), "MONTHLY".into(), "--metrics".into(), "UnblendedCost".into(), "--output".into(), "json".into()
    ]).await;
    push_api_check(report, "budget-and-cost", &cost, |_| "read current-month AWS Cost Explorer spend".to_string());
    if let Ok(body) = &cost {
        if let Some(amount) = body.pointer("/ResultsByTime/0/Total/UnblendedCost/Amount").and_then(Value::as_str).and_then(|value| value.parse::<f64>().ok()) {
            evaluate_budget(report, Provider::Aws, amount, "AWS current-month");
        }
    }
    report.notes.push("Filesystem free-space is only assertable when guest/agent disk metrics exist; CloudWatch ALARM evidence is inspected, but the scanner will not fabricate disk-free data from EBS allocation size.".to_string());
}

async fn scan_gcp(report: &mut ScanReport, scope: Option<&str>) {
    report.transport = "allowlisted gcloud API calls";
    let Some(project) = scope else {
        report.auth_status = "not-configured";
        report.notes.push("Pass scope=<GCP project id>. The scanner never changes the active gcloud project.".to_string());
        return;
    };
    let project_arg = format!("--project={project}");
    let project_body = run_cli("gcloud", vec!["projects".into(), "describe".into(), project.into(), "--format=json".into()]).await;
    if project_body.is_err() {
        report.auth_status = "unavailable";
    } else {
        report.auth_status = "configured";
    }
    push_api_check(report, "authentication", &project_body, |_| format!("GCP project {project} is readable"));

    let instances = run_cli("gcloud", vec!["compute".into(), "instances".into(), "list".into(), project_arg.clone(), "--limit=100".into(), "--format=json".into()]).await;
    push_api_check(report, "compute-inventory", &instances, |body| format!("inspected {} Compute Engine instances (capped at 100)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &instances {
        if let Some(items) = body.as_array() {
            for instance in items {
                let name = instance.get("name").and_then(Value::as_str).unwrap_or("unknown");
                let has_external = instance.get("networkInterfaces").and_then(Value::as_array).is_some_and(|interfaces| interfaces.iter().any(|interface| interface.get("accessConfigs").and_then(Value::as_array).is_some_and(|configs| configs.iter().any(|config| config.get("natIP").and_then(Value::as_str).is_some()))));
                if has_external {
                    add_finding(report, format!("gcp.compute.external-ip.{name}"), Severity::Medium, "security-baseline", "Compute Engine VM has an external IP", "At least one network interface has a NAT external address.", "Prefer private instances with controlled ingress/IAP/load balancing unless direct exposure is intentional.", Some(name.to_string()));
                }
            }
        }
    }

    let disks = run_cli("gcloud", vec!["compute".into(), "disks".into(), "list".into(), project_arg, "--limit=100".into(), "--format=json".into()]).await;
    push_api_check(report, "storage-inventory", &disks, |body| format!("inspected {} persistent disks (capped at 100)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &disks {
        if let Some(items) = body.as_array() {
            for disk in items {
                let name = disk.get("name").and_then(Value::as_str).unwrap_or("unknown");
                if disk.get("users").and_then(Value::as_array).is_none_or(Vec::is_empty) {
                    add_finding(report, format!("gcp.disk.unattached.{name}"), Severity::Low, "budget-and-cost", "Persistent disk appears unattached", "The disk has no users and can continue to incur storage charges.", "Confirm retention/snapshot requirements and remove it through the customer's normal change process if unused.", Some(name.to_string()));
                }
            }
        }
    }
    report.notes.push("For spend trend/forecast, enable Cloud Billing export and grant Billing Account Viewer; for CPU/disk-free checks, grant Monitoring Viewer and expose guest disk metrics. The scanner does not infer those values when telemetry is absent.".to_string());
}

fn with_subscription(mut args: Vec<String>, scope: Option<&str>) -> Vec<String> {
    if let Some(subscription) = scope {
        args.push("--subscription".into());
        args.push(subscription.into());
    }
    args
}

async fn scan_azure(report: &mut ScanReport, scope: Option<&str>) {
    report.transport = "allowlisted az CLI API calls";
    let account = run_cli("az", with_subscription(vec!["account".into(), "show".into(), "-o".into(), "json".into()], scope)).await;
    report.auth_status = if account.is_ok() { "configured" } else { "unavailable" };
    push_api_check(report, "authentication", &account, |body| format!("Azure subscription {} is readable", body.get("id").and_then(Value::as_str).unwrap_or("current")));

    let vms = run_cli("az", with_subscription(vec!["vm".into(), "list".into(), "-d".into(), "--query".into(), "[0:100]".into(), "-o".into(), "json".into()], scope)).await;
    push_api_check(report, "compute-inventory", &vms, |body| format!("inspected {} Azure VMs (capped at 100)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &vms {
        if let Some(items) = body.as_array() {
            for vm in items {
                let id = vm.get("id").and_then(Value::as_str).or_else(|| vm.get("name").and_then(Value::as_str)).unwrap_or("unknown");
                let public_ip = vm.get("publicIps").and_then(Value::as_str).filter(|value| !value.is_empty());
                if public_ip.is_some() {
                    add_finding(report, format!("azure.vm.public-ip.{id}"), Severity::Medium, "security-baseline", "Azure VM has a public IP", "The VM detail response exposes a public IP.", "Prefer private networking plus controlled ingress/Bastion/load balancing unless public exposure is intentional.", Some(id.to_string()));
                }
            }
        }
    }

    let disks = run_cli("az", with_subscription(vec!["disk".into(), "list".into(), "--query".into(), "[0:100]".into(), "-o".into(), "json".into()], scope)).await;
    push_api_check(report, "storage-inventory", &disks, |body| format!("inspected {} managed disks (capped at 100)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &disks {
        if let Some(items) = body.as_array() {
            for disk in items {
                let id = disk.get("id").and_then(Value::as_str).or_else(|| disk.get("name").and_then(Value::as_str)).unwrap_or("unknown");
                if disk.get("managedBy").is_none_or(Value::is_null) {
                    add_finding(report, format!("azure.disk.unattached.{id}"), Severity::Low, "budget-and-cost", "Azure managed disk appears unattached", "managedBy is null.", "Confirm retention requirements and remove/archive it through the customer's normal change process if unused.", Some(id.to_string()));
                }
            }
        }
    }

    let usage = run_cli("az", with_subscription(vec!["consumption".into(), "usage".into(), "list".into(), "--query".into(), "[0:500]".into(), "-o".into(), "json".into()], scope)).await;
    push_api_check(report, "budget-and-cost", &usage, |body| format!("read {} consumption records (capped at 500)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &usage {
        if let Some(items) = body.as_array() {
            let spend: f64 = items.iter().filter_map(|item| item.get("pretaxCost").or_else(|| item.get("cost")).and_then(Value::as_f64)).sum();
            if spend > 0.0 {
                evaluate_budget(report, Provider::Azure, spend, "Azure returned-period");
            }
        }
    }

    let advisor = run_cli("az", with_subscription(vec!["advisor".into(), "recommendation".into(), "list".into(), "--query".into(), "[0:100]".into(), "-o".into(), "json".into()], scope)).await;
    push_api_check(report, "best-practices", &advisor, |body| format!("read {} Azure Advisor recommendations (capped at 100)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &advisor {
        if let Some(items) = body.as_array() {
            for (index, item) in items.iter().enumerate() {
                let category = item.get("category").and_then(Value::as_str).unwrap_or("Advisor");
                let title = item.pointer("/shortDescription/problem").and_then(Value::as_str).or_else(|| item.pointer("/shortDescription/solution").and_then(Value::as_str)).unwrap_or("Azure Advisor recommendation");
                let severity = match category.to_ascii_lowercase().as_str() {
                    "security" | "highavailability" => Severity::High,
                    "cost" | "performance" => Severity::Medium,
                    _ => Severity::Low,
                };
                add_finding(report, format!("azure.advisor.{index}"), severity, "best-practices", title, format!("Azure Advisor category: {category}."), "Review and apply the recommendation through normal change control after validating workload impact.", item.get("resourceMetadata").and_then(|v| v.get("resourceId")).and_then(Value::as_str).map(str::to_string));
            }
        }
    }
    report.notes.push("Direct filesystem free-space requires Azure Monitor guest metrics/VM Insights. The scanner keeps this check unknown when the guest metric is absent rather than treating disk allocation size as free space.".to_string());
}

async fn scan_cloudflare(client: &reqwest::Client, report: &mut ScanReport) {
    report.transport = "HTTPS GET only";
    let Some(token) = env_token("CLOUDFLARE_API_TOKEN") else {
        missing_auth(report, "CLOUDFLARE_API_TOKEN", "Use a Cloudflare API token containing only the required Account/Zone Read permission groups; do not use the Global API Key.");
        return;
    };
    report.auth_status = "configured";
    let accounts = get_json(client, "https://api.cloudflare.com/client/v4/accounts?per_page=50", &["api.cloudflare.com"], Some(&token), None).await;
    push_api_check(report, "account-inventory", &accounts, |body| format!("{} Cloudflare accounts visible", array_len(body, "result")));
    let zones = get_json(client, "https://api.cloudflare.com/client/v4/zones?per_page=100", &["api.cloudflare.com"], Some(&token), None).await;
    push_api_check(report, "zone-inventory", &zones, |body| format!("{} Cloudflare zones visible (capped at 100)", array_len(body, "result")));
    if let Ok(body) = &zones {
        if let Some(items) = body.get("result").and_then(Value::as_array) {
            for zone in items {
                let name = zone.get("name").and_then(Value::as_str).unwrap_or("unknown");
                let status = zone.get("status").and_then(Value::as_str).unwrap_or("unknown");
                if status != "active" {
                    add_finding(report, format!("cloudflare.zone.status.{name}"), Severity::High, "reliability-and-backups", format!("Cloudflare zone {name} is not active"), format!("Zone status is {status:?}."), "Check nameserver delegation, zone activation, and account state.", Some(name.to_string()));
                }
            }
        }
    }
    report.notes.push("Grant Analytics Read for traffic/error/utilization checks and the minimum Billing Read group required for cost posture; the scanner never requests an Edit permission.".to_string());
}

async fn scan_github(client: &reqwest::Client, report: &mut ScanReport, scope: Option<&str>) {
    report.transport = "HTTPS GET only";
    let Some(org) = scope else {
        report.auth_status = "not-configured";
        report.notes.push("Pass scope=<GitHub organization>. Use a fine-grained PAT or GitHub App with read-only organization/repository permissions.".to_string());
        return;
    };
    let token = env_token("GITHUB_TOKEN").or_else(|| env_token("GH_TOKEN"));
    report.auth_status = if token.is_some() { "configured" } else { "anonymous-public-only" };
    let organization = get_json(client, &format!("https://api.github.com/orgs/{org}"), &["api.github.com"], token.as_deref(), Some("application/vnd.github+json")).await;
    push_api_check(report, "organization", &organization, |_| format!("GitHub organization {org} is readable"));
    let repos = get_json(client, &format!("https://api.github.com/orgs/{org}/repos?per_page=100&type=all"), &["api.github.com"], token.as_deref(), Some("application/vnd.github+json")).await;
    push_api_check(report, "repository-inventory", &repos, |body| format!("{} repositories inspected (first page, max 100)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &repos {
        if let Some(items) = body.as_array() {
            for repo in items {
                let name = repo.get("full_name").and_then(Value::as_str).unwrap_or("unknown");
                if repo.get("archived").and_then(Value::as_bool) == Some(true) {
                    add_finding(report, format!("github.repo.archived.{name}"), Severity::Info, "resource-inventory", "Repository is archived", "Archived repositories are read-only and should be excluded from active delivery expectations.", "Confirm the repository is intentionally archived and remove it from active deployment/SLI inventories.", Some(name.to_string()));
                }
                if repo.get("has_discussions").and_then(Value::as_bool) == Some(false) && repo.get("has_issues").and_then(Value::as_bool) == Some(false) {
                    add_finding(report, format!("github.repo.no-tracker.{name}"), Severity::Low, "best-practices", "Repository has neither Issues nor Discussions enabled", "There is no repository-native issue/discussion intake surface.", "Confirm work tracking is intentionally external (for example Linear); otherwise enable a supported intake path.", Some(name.to_string()));
                }
            }
        }
    }
    report.notes.push("Branch protection/rulesets, Actions settings, Dependabot/code scanning, secret scanning, billing usage, and org audit-log checks are capability-gated: grant only the corresponding GitHub read permissions when those checks are required.".to_string());
}

fn parse_info(result: &Value) -> std::collections::HashMap<String, String> {
    let text = result.get("result").and_then(Value::as_str).unwrap_or_default();
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

async fn scan_upstash(client: &reqwest::Client, report: &mut ScanReport) {
    report.transport = "HTTPS GET only";
    let Some(base) = env_token("UPSTASH_REDIS_REST_URL") else {
        missing_auth(report, "UPSTASH_REDIS_REST_URL", "Set the Redis REST URL and the separate Upstash Read Only token. The Standard token is intentionally unsupported.");
        return;
    };
    let Some(token) = env_token("UPSTASH_REDIS_REST_READ_ONLY_TOKEN") else {
        missing_auth(report, "UPSTASH_REDIS_REST_READ_ONLY_TOKEN", "Use Upstash's Read Only REST token; do not place the Standard token in the audit environment.");
        return;
    };
    let info_url = format!("{}/info", base.trim_end_matches('/'));
    let info = get_json(client, &info_url, &["upstash.io"], Some(&token), None).await;
    report.auth_status = if info.is_ok() { "configured-read-only-token" } else { "error" };
    push_api_check(report, "redis-info", &info, |_| "Upstash Redis INFO is readable with the read-only token".to_string());
    if let Ok(body) = &info {
        let parsed = parse_info(body);
        let used = parsed.get("used_memory").and_then(|v| v.parse::<f64>().ok());
        let max = parsed.get("maxmemory").and_then(|v| v.parse::<f64>().ok());
        if let (Some(used), Some(max)) = (used, max) {
            if max > 0.0 {
                let pct = used / max * 100.0;
                if pct >= 90.0 {
                    add_finding(report, "upstash.memory.critical", Severity::Critical, "utilization-and-capacity", format!("Redis memory utilization is {pct:.1}%"), "used_memory is at least 90% of maxmemory.", "Reduce memory pressure, validate eviction policy, remove stale keys through normal change control, or increase capacity before writes fail/evictions accelerate.", None);
                } else if pct >= 80.0 {
                    add_finding(report, "upstash.memory.high", Severity::High, "utilization-and-capacity", format!("Redis memory utilization is {pct:.1}%"), "used_memory is at least 80% of maxmemory.", "Investigate key growth, TTL coverage, eviction policy, and capacity headroom.", None);
                }
            }
        }
        if parsed.get("evicted_keys").and_then(|v| v.parse::<u64>().ok()).is_some_and(|v| v > 0) {
            add_finding(report, "upstash.evictions", Severity::Medium, "utilization-and-capacity", "Redis reports evicted keys", "evicted_keys is non-zero.", "Review memory pressure, TTLs, eviction policy, and workload sizing; correlate with application cache misses/errors.", None);
        }
    }
}

async fn scan_vercel(client: &reqwest::Client, report: &mut ScanReport) {
    report.transport = "HTTPS GET only";
    let Some(token) = env_token("VERCEL_AUDIT_TOKEN") else {
        missing_auth(report, "VERCEL_AUDIT_TOKEN", "Use a dedicated Vercel audit identity/token. Even if the provider token can technically mutate, this adapter has no non-GET code path.");
        return;
    };
    report.auth_status = "configured";
    let projects = get_json(client, "https://api.vercel.com/v9/projects?limit=100", &["api.vercel.com"], Some(&token), None).await;
    push_api_check(report, "project-inventory", &projects, |body| format!("{} Vercel projects inspected (capped at 100)", array_len(body, "projects")));
    let deployments = get_json(client, "https://api.vercel.com/v6/deployments?limit=100", &["api.vercel.com"], Some(&token), None).await;
    push_api_check(report, "deployment-health", &deployments, |body| format!("{} Vercel deployments inspected (capped at 100)", array_len(body, "deployments")));
    if let Ok(body) = &deployments {
        if let Some(items) = body.get("deployments").and_then(Value::as_array) {
            for deployment in items {
                let uid = deployment.get("uid").and_then(Value::as_str).unwrap_or("unknown");
                let state = deployment.get("state").or_else(|| deployment.get("readyState")).and_then(Value::as_str).unwrap_or("unknown");
                if matches!(state, "ERROR" | "CANCELED") {
                    add_finding(report, format!("vercel.deployment.{uid}"), Severity::Medium, "reliability-and-backups", format!("Vercel deployment is {state}"), "A recent deployment did not become ready.", "Inspect build/runtime logs and rollback/redeploy through the customer's normal deployment workflow if needed.", Some(uid.to_string()));
                }
            }
        }
    }
}

async fn scan_digitalocean(client: &reqwest::Client, report: &mut ScanReport) {
    report.transport = "HTTPS GET only";
    let Some(token) = env_token("DIGITALOCEAN_READ_ONLY_TOKEN") else {
        missing_auth(report, "DIGITALOCEAN_READ_ONLY_TOKEN", "Create a DigitalOcean Read Only token (api:read) or narrower resource :read scopes.");
        return;
    };
    report.auth_status = "configured-read-only-token";
    let droplets = get_json(client, "https://api.digitalocean.com/v2/droplets?per_page=100", &["api.digitalocean.com"], Some(&token), None).await;
    push_api_check(report, "compute-inventory", &droplets, |body| format!("{} Droplets inspected (capped at 100)", array_len(body, "droplets")));
    if let Ok(body) = &droplets {
        if let Some(items) = body.get("droplets").and_then(Value::as_array) {
            for droplet in items {
                let id = droplet.get("id").map(Value::to_string).unwrap_or_else(|| "unknown".to_string());
                let backups = droplet.get("features").and_then(Value::as_array).is_some_and(|features| features.iter().any(|feature| feature.as_str() == Some("backups")));
                if !backups {
                    add_finding(report, format!("digitalocean.backups.{id}"), Severity::Medium, "reliability-and-backups", "Droplet backups are not enabled", "The Droplet feature list does not contain backups.", "Confirm recovery objectives; enable/provider-independent backups through normal change control when the workload is stateful or cannot be rebuilt quickly.", Some(id));
                }
            }
        }
    }
    let volumes = get_json(client, "https://api.digitalocean.com/v2/volumes?per_page=100", &["api.digitalocean.com"], Some(&token), None).await;
    push_api_check(report, "storage-inventory", &volumes, |body| format!("{} block volumes inspected (capped at 100)", array_len(body, "volumes")));
    if let Ok(body) = &volumes {
        if let Some(items) = body.get("volumes").and_then(Value::as_array) {
            for volume in items {
                let id = volume.get("id").and_then(Value::as_str).unwrap_or("unknown");
                if volume.get("droplet_ids").and_then(Value::as_array).is_none_or(Vec::is_empty) {
                    add_finding(report, format!("digitalocean.volume.unattached.{id}"), Severity::Low, "budget-and-cost", "Block volume appears unattached", "droplet_ids is empty.", "Confirm retention/snapshot needs and remove it through normal change control if unused.", Some(id.to_string()));
                }
            }
        }
    }
    let balance = get_json(client, "https://api.digitalocean.com/v2/customers/my/balance", &["api.digitalocean.com"], Some(&token), None).await;
    push_api_check(report, "budget-and-cost", &balance, |_| "DigitalOcean billing balance is readable".to_string());
    if let Ok(body) = &balance {
        if let Some(spend) = body.get("month_to_date_usage").and_then(Value::as_str).and_then(|v| v.parse::<f64>().ok()) {
            evaluate_budget(report, Provider::DigitalOcean, spend, "DigitalOcean month-to-date");
        }
    }
}

async fn scan_netlify(client: &reqwest::Client, report: &mut ScanReport) {
    report.transport = "HTTPS GET only";
    let Some(token) = env_token("NETLIFY_AUDIT_TOKEN") else {
        missing_auth(report, "NETLIFY_AUDIT_TOKEN", "Use a dedicated Netlify audit identity/token. This adapter can issue GET requests only.");
        return;
    };
    report.auth_status = "configured";
    let sites = get_json(client, "https://api.netlify.com/api/v1/sites?per_page=100", &["api.netlify.com"], Some(&token), None).await;
    push_api_check(report, "site-inventory", &sites, |body| format!("{} Netlify sites inspected (capped at 100)", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &sites {
        if let Some(items) = body.as_array() {
            for site in items {
                let id = site.get("id").and_then(Value::as_str).unwrap_or("unknown");
                if site.get("force_ssl").and_then(Value::as_bool) == Some(false) {
                    add_finding(report, format!("netlify.force-ssl.{id}"), Severity::High, "security-baseline", "Netlify site does not force HTTPS", "force_ssl is false.", "Enable forced HTTPS after validating custom-domain certificates and redirects.", Some(id.to_string()));
                }
            }
        }
    }
}

async fn scan_render(client: &reqwest::Client, report: &mut ScanReport) {
    report.transport = "HTTPS GET only";
    let Some(token) = env_token("RENDER_AUDIT_TOKEN") else {
        missing_auth(report, "RENDER_AUDIT_TOKEN", "Use a dedicated Render audit identity/API key. This adapter can issue GET requests only.");
        return;
    };
    report.auth_status = "configured";
    let services = get_json(client, "https://api.render.com/v1/services?limit=100", &["api.render.com"], Some(&token), Some("application/json")).await;
    push_api_check(report, "service-inventory", &services, |body| format!("{} Render service records inspected (capped at 100)", body.as_array().map_or(0, Vec::len)));
    report.notes.push("Render metrics/cost checks are reported only when their read APIs are available to the supplied audit identity; no deployment/restart/update endpoint exists in this adapter.".to_string());
}

async fn scan_fly(report: &mut ScanReport, scope: Option<&str>) {
    report.transport = "allowlisted flyctl read calls";
    let Some(org) = scope else {
        report.auth_status = "not-configured";
        report.notes.push("Pass scope=<Fly.io organization slug>; the scanner invokes only `fly apps list --org ... --json`.".to_string());
        return;
    };
    let apps = run_cli("fly", vec!["apps".into(), "list".into(), "--org".into(), org.into(), "--json".into()]).await;
    report.auth_status = if apps.is_ok() { "configured" } else { "unavailable" };
    push_api_check(report, "app-inventory", &apps, |body| format!("{} Fly.io apps visible", body.as_array().map_or(0, Vec::len)));
    report.notes.push("Per-app machine/volume/metric checks will only use additional exact read subcommands; this adapter deliberately has no deploy, scale, restart, secrets, or machine mutation command path.".to_string());
}

async fn scan_heroku(client: &reqwest::Client, report: &mut ScanReport) {
    report.transport = "HTTPS GET only";
    let Some(token) = env_token("HEROKU_READ_ONLY_TOKEN") else {
        missing_auth(report, "HEROKU_READ_ONLY_TOKEN", "Use a Heroku OAuth token created with the read scope.");
        return;
    };
    report.auth_status = "configured-read-scope-token";
    let apps = get_json(client, "https://api.heroku.com/apps", &["api.heroku.com"], Some(&token), Some("application/vnd.heroku+json; version=3")).await;
    push_api_check(report, "app-inventory", &apps, |body| format!("{} Heroku apps visible", body.as_array().map_or(0, Vec::len)));
    if let Ok(body) = &apps {
        if let Some(items) = body.as_array() {
            for app in items {
                let id = app.get("id").and_then(Value::as_str).unwrap_or("unknown");
                if app.get("maintenance").and_then(Value::as_bool) == Some(true) {
                    add_finding(report, format!("heroku.maintenance.{id}"), Severity::Medium, "reliability-and-backups", "Heroku app is in maintenance mode", "maintenance=true.", "Confirm whether maintenance is intentional and correlate with deployment/incident records.", Some(id.to_string()));
                }
            }
        }
    }
}

pub async fn scan(client: &reqwest::Client, provider: Provider, scope: Option<&str>) -> Result<ScanReport, String> {
    let scope = validate_scope(scope)?;
    let transport = catalog().into_iter().find(|profile| profile.provider == provider.as_str()).map(|profile| profile.primary_transport).unwrap_or("read-only");
    let mut report = blank_report(provider, scope, transport);
    match provider {
        Provider::Aws => scan_aws(&mut report).await,
        Provider::Gcp => scan_gcp(&mut report, scope).await,
        Provider::Azure => scan_azure(&mut report, scope).await,
        Provider::Cloudflare => scan_cloudflare(client, &mut report).await,
        Provider::Github => scan_github(client, &mut report, scope).await,
        Provider::Upstash => scan_upstash(client, &mut report).await,
        Provider::Vercel => scan_vercel(client, &mut report).await,
        Provider::DigitalOcean => scan_digitalocean(client, &mut report).await,
        Provider::Netlify => scan_netlify(client, &mut report).await,
        Provider::Render => scan_render(client, &mut report).await,
        Provider::FlyIo => scan_fly(&mut report, scope).await,
        Provider::Heroku => scan_heroku(client, &mut report).await,
    }
    finalize(&mut report);
    Ok(report)
}

fn default_console(provider: Provider) -> &'static str {
    catalog().into_iter().find(|profile| profile.provider == provider.as_str()).map(|profile| profile.console).unwrap_or("https://canonical.cloud/")
}

fn console_host_allowed(provider: Provider, host: &str) -> bool {
    match provider {
        Provider::Aws => host == "console.aws.amazon.com" || host.ends_with(".console.aws.amazon.com") || host.ends_with(".signin.aws.amazon.com"),
        Provider::Gcp => matches!(host, "console.cloud.google.com" | "accounts.google.com"),
        Provider::Azure => matches!(host, "portal.azure.com" | "login.microsoftonline.com"),
        Provider::Cloudflare => host == "dash.cloudflare.com",
        Provider::Github => matches!(host, "github.com" | "githubusercontent.com"),
        Provider::Upstash => host == "console.upstash.com",
        Provider::Vercel => host == "vercel.com" || host.ends_with(".vercel.com"),
        Provider::DigitalOcean => host == "cloud.digitalocean.com",
        Provider::Netlify => host == "app.netlify.com",
        Provider::Render => host == "dashboard.render.com",
        Provider::FlyIo => host == "fly.io" || host.ends_with(".fly.io"),
        Provider::Heroku => host == "dashboard.heroku.com" || host.ends_with(".heroku.com"),
    }
}

fn validate_console_url(provider: Provider, url: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|error| format!("invalid console URL: {error}"))?;
    if parsed.scheme() != "https" {
        return Err("browser readiness URL must use https".to_string());
    }
    let host = parsed.host_str().ok_or_else(|| "browser readiness URL has no host".to_string())?;
    if !console_host_allowed(provider, host) {
        return Err(format!("console host {host:?} is not allowlisted for {}", provider.as_str()));
    }
    Ok(parsed)
}

pub async fn browser_scan(provider: Provider, engine: BrowserEngine, url: Option<&str>) -> Result<Value, String> {
    let target = url.unwrap_or_else(|| default_console(provider));
    let target = validate_console_url(provider, target)?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("browser/readiness-audit.mjs");
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        Command::new("node")
            .arg(script)
            .arg("--engine")
            .arg(engine.as_str())
            .arg("--provider")
            .arg(provider.as_str())
            .arg("--url")
            .arg(target.as_str())
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "browser readiness helper timed out".to_string())?
    .map_err(|error| format!("failed to run browser helper: {error}"))?;
    if !output.status.success() {
        return Err(format!("browser readiness helper exited {}: {}", output.status, truncate_text(&output.stderr, 1600)));
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err("browser readiness output exceeded 1 MiB".to_string());
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("browser readiness helper returned invalid JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_has_twelve_distinct_providers() {
        let profiles = catalog();
        assert_eq!(profiles.len(), 12);
        let mut names: Vec<_> = profiles.iter().map(|profile| profile.provider).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 12);
    }

    #[test]
    fn console_allowlist_rejects_cross_provider_hosts() {
        assert!(validate_console_url(Provider::Aws, "https://console.aws.amazon.com/").is_ok());
        assert!(validate_console_url(Provider::Aws, "https://portal.azure.com/").is_err());
        assert!(validate_console_url(Provider::Github, "http://github.com/").is_err());
    }

    #[test]
    fn scope_validation_blocks_shellish_input_even_though_no_shell_is_used() {
        assert_eq!(validate_scope(Some("my-project_123")).unwrap(), Some("my-project_123"));
        assert!(validate_scope(Some("prod; rm -rf /" )).is_err());
        assert!(validate_scope(Some("$(whoami)")).is_err());
    }

    #[test]
    fn parses_upstash_info_without_echoing_tokens() {
        let parsed = parse_info(&json!({"result":"# Memory\nused_memory:80\nmaxmemory:100\nevicted_keys:2\n"}));
        assert_eq!(parsed.get("used_memory").map(String::as_str), Some("80"));
        assert_eq!(parsed.get("evicted_keys").map(String::as_str), Some("2"));
    }
}
