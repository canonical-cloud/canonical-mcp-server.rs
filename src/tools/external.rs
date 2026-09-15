//! Allowlisted wrappers for external open-source readiness scanners.
//!
//! This module intentionally does not expose an arbitrary command, argument,
//! environment, URL, or shell primitive. Each supported tool has an exact
//! executable and argument grammar. Customer-account tools inherit only the
//! caller's already-configured read-only credentials; credentials are never
//! accepted as MCP parameters or rendered into command lines.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::process::Command;

const MAX_EXTERNAL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_FINDINGS: usize = 100;
const DEFAULT_TIMEOUT_SECS: u64 = 180;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalTool {
    Prowler,
    ScoutSuite,
    Trivy,
    Checkov,
    Kubescape,
    KubeBench,
    Kubeaudit,
    Infracost,
    Powerpipe,
}

impl ExternalTool {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prowler => "prowler",
            Self::ScoutSuite => "scout-suite",
            Self::Trivy => "trivy",
            Self::Checkov => "checkov",
            Self::Kubescape => "kubescape",
            Self::KubeBench => "kube-bench",
            Self::Kubeaudit => "kubeaudit",
            Self::Infracost => "infracost",
            Self::Powerpipe => "powerpipe",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalProvider {
    Aws,
    Azure,
    Gcp,
    Kubernetes,
    Github,
    Cloudflare,
    DigitalOcean,
    AlibabaCloud,
    OracleCloud,
    M365,
    Iac,
    MongoDbAtlas,
}

impl ExternalProvider {
    fn prowler_name(self) -> Option<&'static str> {
        match self {
            Self::Aws => Some("aws"),
            Self::Azure => Some("azure"),
            Self::Gcp => Some("gcp"),
            Self::Kubernetes => Some("kubernetes"),
            Self::Github => Some("github"),
            Self::Cloudflare => Some("cloudflare"),
            Self::AlibabaCloud => Some("alibabacloud"),
            Self::OracleCloud => Some("oraclecloud"),
            Self::M365 => Some("m365"),
            Self::Iac => Some("iac"),
            Self::MongoDbAtlas => Some("mongodbatlas"),
            Self::DigitalOcean => None,
        }
    }

    fn scout_name(self) -> Option<&'static str> {
        match self {
            Self::Aws => Some("aws"),
            Self::Azure => Some("azure"),
            Self::Gcp => Some("gcp"),
            Self::Kubernetes => Some("kubernetes"),
            Self::DigitalOcean => Some("digitalocean"),
            Self::AlibabaCloud => Some("aliyun"),
            Self::OracleCloud => Some("oci"),
            Self::Github
            | Self::Cloudflare
            | Self::M365
            | Self::Iac
            | Self::MongoDbAtlas => None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ExternalToolProfile {
    pub tool: &'static str,
    pub purpose: &'static str,
    pub execution: &'static str,
    pub account_access: &'static str,
    pub supported_targets: &'static [&'static str],
    pub output: &'static str,
    pub customer_mutations: bool,
}

pub fn catalog() -> Vec<ExternalToolProfile> {
    vec![
        ExternalToolProfile {
            tool: "prowler",
            purpose: "multi-cloud security, compliance, and posture assessment",
            execution: "prowler <allowlisted-provider> with JSON-OCSF output",
            account_access: "inherits provider credentials; configure those credentials read-only",
            supported_targets: &["aws", "azure", "gcp", "kubernetes", "github", "cloudflare", "alibaba-cloud", "oracle-cloud", "m365", "iac", "mongodb-atlas"],
            output: "JSON-OCSF normalized into Canonical findings",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "scout-suite",
            purpose: "independent point-in-time multi-cloud attack-surface audit",
            execution: "scout <allowlisted-provider> --no-browser into an isolated temporary report directory",
            account_access: "inherits provider credentials; configure those credentials read-only",
            supported_targets: &["aws", "azure", "gcp", "kubernetes", "digital-ocean", "alibaba-cloud", "oracle-cloud"],
            output: "report-generation evidence and bounded stdout/stderr metadata",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "trivy",
            purpose: "IaC misconfiguration scanning",
            execution: "trivy config --format json <validated-local-target>",
            account_access: "none; local repository/configuration scan",
            supported_targets: &["terraform", "cloudformation", "arm", "kubernetes", "helm", "dockerfile"],
            output: "JSON misconfigurations normalized into Canonical findings",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "checkov",
            purpose: "IaC policy-as-code and graph checks",
            execution: "checkov -d <validated-local-target> -o json",
            account_access: "none; local repository/configuration scan",
            supported_targets: &["terraform", "cloudformation", "kubernetes", "helm", "arm", "bicep", "opentofu", "github-actions"],
            output: "JSON failed checks normalized into Canonical findings",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "kubescape",
            purpose: "Kubernetes configuration and framework scanning",
            execution: "kubescape scan [validated-local-target] --format json --format-version v2",
            account_access: "current kubeconfig for cluster mode; grant read-only Kubernetes RBAC",
            supported_targets: &["current-cluster", "kubernetes-yaml", "helm", "kustomize"],
            output: "JSON controls normalized by status",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "kube-bench",
            purpose: "CIS Kubernetes benchmark checks",
            execution: "kube-bench --json",
            account_access: "local/node and Kubernetes configuration reads only",
            supported_targets: &["kubernetes-node", "kubernetes-cluster"],
            output: "JSON CIS results normalized by PASS/WARN/FAIL",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "kubeaudit",
            purpose: "Kubernetes workload security best-practice audit",
            execution: "kubeaudit all [validated manifest] --format json",
            account_access: "current kubeconfig for cluster mode; grant read-only Kubernetes RBAC",
            supported_targets: &["current-cluster", "kubernetes-yaml"],
            output: "JSON/NDJSON audit findings normalized into Canonical findings",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "infracost",
            purpose: "pre-deploy cloud cost estimation and FinOps evidence",
            execution: "infracost breakdown --path <validated-local-target> --format json",
            account_access: "no cloud-account credentials required for normal IaC pricing",
            supported_targets: &["terraform", "terraform-plan-json"],
            output: "JSON monthly cost estimate",
            customer_mutations: false,
        },
        ExternalToolProfile {
            tool: "powerpipe",
            purpose: "benchmark-as-code over Steampipe connections",
            execution: "powerpipe benchmark run <validated-benchmark-id> --output json",
            account_access: "Steampipe provider credentials must be configured read-only",
            supported_targets: &["aws", "azure", "gcp", "github", "kubernetes", "m365", "oci", "other installed compliance mods"],
            output: "JSON benchmark statuses normalized by ok/alarm/skip/error",
            customer_mutations: false,
        },
    ]
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExternalSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize)]
pub struct ExternalFinding {
    pub id: String,
    pub severity: ExternalSeverity,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct ExternalCounts {
    pub passed: usize,
    pub failed: usize,
    pub warning: usize,
    pub skipped: usize,
    pub informational: usize,
    pub total_records: usize,
}

#[derive(Debug, Serialize)]
pub struct ExternalScanReport {
    pub tool: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub status: &'static str,
    pub read_only: bool,
    pub executable: String,
    pub arguments: Vec<String>,
    pub exit_code: Option<i32>,
    pub counts: ExternalCounts,
    pub findings: Vec<ExternalFinding>,
    pub notes: Vec<String>,
}

#[derive(Debug)]
struct ProcessOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn timeout_secs() -> u64 {
    std::env::var("CANONICAL_EXTERNAL_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(10, 600))
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

fn truncate_text(bytes: &[u8], max_chars: usize) -> String {
    String::from_utf8_lossy(bytes).chars().take(max_chars).collect()
}

async fn run_process(program: &str, args: &[String]) -> Result<ProcessOutput, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(timeout_secs()),
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("{program} scan timed out"))?
    .map_err(|error| format!("failed to run {program}: {error}"))?;

    if output.stdout.len() > MAX_EXTERNAL_OUTPUT_BYTES {
        return Err(format!(
            "{program} stdout exceeded {MAX_EXTERNAL_OUTPUT_BYTES} byte limit"
        ));
    }
    if output.stderr.len() > MAX_EXTERNAL_OUTPUT_BYTES {
        return Err(format!(
            "{program} stderr exceeded {MAX_EXTERNAL_OUTPUT_BYTES} byte limit"
        ));
    }

    Ok(ProcessOutput {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn audit_root() -> Result<PathBuf, String> {
    let configured = std::env::var("CANONICAL_AUDIT_ROOT").unwrap_or_else(|_| ".".to_string());
    fs::canonicalize(&configured)
        .map_err(|error| format!("cannot resolve CANONICAL_AUDIT_ROOT {configured:?}: {error}"))
}

fn validated_target(target: &str) -> Result<PathBuf, String> {
    if target.trim().is_empty() || target.len() > 1024 {
        return Err("target path must be 1..=1024 characters".to_string());
    }
    if target.contains('\0') {
        return Err("target path contains NUL".to_string());
    }
    let root = audit_root()?;
    let requested = Path::new(target);
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    let resolved = fs::canonicalize(&joined)
        .map_err(|error| format!("cannot resolve audit target {}: {error}", joined.display()))?;
    if !resolved.starts_with(&root) {
        return Err(format!(
            "audit target {} escapes CANONICAL_AUDIT_ROOT {}",
            resolved.display(),
            root.display()
        ));
    }
    Ok(resolved)
}

fn validate_benchmark(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 {
        return Err("benchmark id must be 1..=200 characters".to_string());
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("benchmark id contains unsupported characters".to_string());
    }
    Ok(value.to_string())
}

fn temporary_report_dir(tool: ExternalTool) -> Result<PathBuf, String> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock error: {error}"))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "canonical-readiness-{}-{}-{epoch}",
        tool.as_str(),
        std::process::id()
    ));
    fs::create_dir(&path)
        .map_err(|error| format!("cannot create temporary report directory: {error}"))?;
    Ok(path)
}

fn json_or_ndjson(bytes: &[u8]) -> Result<Value, String> {
    if let Ok(value) = serde_json::from_slice(bytes) {
        return Ok(value);
    }
    let text = String::from_utf8_lossy(bytes);
    let mut rows = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("external tool returned invalid JSON/NDJSON: {error}"))?;
        rows.push(value);
    }
    if rows.is_empty() {
        Err("external tool returned no JSON records".to_string())
    } else {
        Ok(Value::Array(rows))
    }
}

fn severity_from_text(value: Option<&str>) -> ExternalSeverity {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "critical" | "fatal" => ExternalSeverity::Critical,
        "high" | "error" | "fail" | "failed" | "alarm" => ExternalSeverity::High,
        "medium" | "warning" | "warn" => ExternalSeverity::Medium,
        "low" => ExternalSeverity::Low,
        _ => ExternalSeverity::Info,
    }
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
}

fn push_finding(
    findings: &mut Vec<ExternalFinding>,
    id: impl Into<String>,
    severity: ExternalSeverity,
    title: impl Into<String>,
    detail: impl Into<String>,
    resource: Option<String>,
) {
    if findings.len() >= MAX_FINDINGS {
        return;
    }
    findings.push(ExternalFinding {
        id: id.into(),
        severity,
        title: title.into(),
        detail: detail.into(),
        resource,
    });
}

fn walk_statuses(value: &Value, counts: &mut ExternalCounts, findings: &mut Vec<ExternalFinding>) {
    match value {
        Value::Array(values) => {
            for value in values {
                walk_statuses(value, counts, findings);
            }
        }
        Value::Object(object) => {
            let status = string_field(object, &["status", "Status", "result", "Result"])
                .map(|value| value.to_ascii_lowercase());
            if let Some(status) = status.as_deref() {
                match status {
                    "ok" | "pass" | "passed" | "success" => counts.passed += 1,
                    "alarm" | "fail" | "failed" | "error" => {
                        counts.failed += 1;
                        let title = string_field(
                            object,
                            &["title", "Title", "name", "check_name", "test_desc", "reason"],
                        )
                        .unwrap_or("External tool reported a failing control");
                        let detail = string_field(
                            object,
                            &["reason", "message", "Message", "description", "remediation"],
                        )
                        .unwrap_or(title);
                        let resource = string_field(
                            object,
                            &["resource", "resource_id", "resourceName", "Resource"],
                        )
                        .map(str::to_string);
                        push_finding(
                            findings,
                            format!("external.status.{}", counts.failed),
                            severity_from_text(Some(status)),
                            title,
                            detail,
                            resource,
                        );
                    }
                    "warn" | "warning" => counts.warning += 1,
                    "skip" | "skipped" | "not-applicable" => counts.skipped += 1,
                    "info" | "informational" => counts.informational += 1,
                    _ => {}
                }
            }
            for child in object.values() {
                if child.is_array() || child.is_object() {
                    walk_statuses(child, counts, findings);
                }
            }
        }
        _ => {}
    }
}

fn parse_trivy(value: &Value, counts: &mut ExternalCounts, findings: &mut Vec<ExternalFinding>) {
    let Some(results) = value.get("Results").and_then(Value::as_array) else {
        walk_statuses(value, counts, findings);
        return;
    };
    for result in results {
        let target = result.get("Target").and_then(Value::as_str);
        for key in ["Misconfigurations", "Vulnerabilities", "Secrets"] {
            let Some(items) = result.get(key).and_then(Value::as_array) else {
                continue;
            };
            for item in items {
                counts.failed += 1;
                counts.total_records += 1;
                let id = item
                    .get("ID")
                    .or_else(|| item.get("VulnerabilityID"))
                    .and_then(Value::as_str)
                    .unwrap_or("trivy.finding");
                let title = item
                    .get("Title")
                    .or_else(|| item.get("Message"))
                    .and_then(Value::as_str)
                    .unwrap_or("Trivy finding");
                let detail = item
                    .get("Description")
                    .or_else(|| item.get("Message"))
                    .or_else(|| item.get("Resolution"))
                    .and_then(Value::as_str)
                    .unwrap_or(title);
                let severity = severity_from_text(item.get("Severity").and_then(Value::as_str));
                push_finding(
                    findings,
                    id,
                    severity,
                    title,
                    detail,
                    target.map(str::to_string),
                );
            }
        }
    }
}

fn collect_checkov_failed(value: &Value, counts: &mut ExternalCounts, findings: &mut Vec<ExternalFinding>) {
    match value {
        Value::Array(values) => {
            for child in values {
                collect_checkov_failed(child, counts, findings);
            }
        }
        Value::Object(object) => {
            if let Some(results) = object.get("results").and_then(Value::as_object) {
                if let Some(passed) = results.get("passed_checks").and_then(Value::as_array) {
                    counts.passed += passed.len();
                    counts.total_records += passed.len();
                }
                if let Some(skipped) = results.get("skipped_checks").and_then(Value::as_array) {
                    counts.skipped += skipped.len();
                    counts.total_records += skipped.len();
                }
                if let Some(failed) = results.get("failed_checks").and_then(Value::as_array) {
                    counts.failed += failed.len();
                    counts.total_records += failed.len();
                    for row in failed.iter().take(MAX_FINDINGS.saturating_sub(findings.len())) {
                        let row = row.as_object();
                        let id = row
                            .and_then(|row| string_field(row, &["check_id"]))
                            .unwrap_or("checkov.failed");
                        let title = row
                            .and_then(|row| string_field(row, &["check_name"]))
                            .unwrap_or("Checkov failed policy");
                        let detail = row
                            .and_then(|row| string_field(row, &["guideline", "check_name"]))
                            .unwrap_or(title);
                        let resource = row
                            .and_then(|row| string_field(row, &["resource", "file_path"]))
                            .map(str::to_string);
                        push_finding(
                            findings,
                            id,
                            ExternalSeverity::High,
                            title,
                            detail,
                            resource,
                        );
                    }
                }
            }
            for child in object.values() {
                if child.is_array() || child.is_object() {
                    collect_checkov_failed(child, counts, findings);
                }
            }
        }
        _ => {}
    }
}

fn collect_kubeaudit(value: &Value, counts: &mut ExternalCounts, findings: &mut Vec<ExternalFinding>) {
    match value {
        Value::Array(values) => {
            for child in values {
                collect_kubeaudit(child, counts, findings);
            }
        }
        Value::Object(object) => {
            if let Some(level) = string_field(object, &["level", "Level", "severity", "Severity"])
            {
                counts.total_records += 1;
                match level.to_ascii_lowercase().as_str() {
                    "error" => counts.failed += 1,
                    "warning" | "warn" => counts.warning += 1,
                    _ => counts.informational += 1,
                }
                if matches!(level.to_ascii_lowercase().as_str(), "error" | "warning" | "warn") {
                    let title = string_field(
                        object,
                        &["auditResultName", "AuditResultName", "message", "Message"],
                    )
                    .unwrap_or("Kubeaudit finding");
                    let detail = string_field(object, &["message", "Message"]).unwrap_or(title);
                    let resource = string_field(
                        object,
                        &["resourceName", "ResourceName", "container", "Container"],
                    )
                    .map(str::to_string);
                    push_finding(
                        findings,
                        format!("kubeaudit.{}", counts.total_records),
                        severity_from_text(Some(level)),
                        title,
                        detail,
                        resource,
                    );
                }
            }
        }
        _ => {}
    }
}

fn parse_infracost(value: &Value, counts: &mut ExternalCounts, findings: &mut Vec<ExternalFinding>) {
    let total = value
        .get("totalMonthlyCost")
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("projects")
                .and_then(Value::as_array)
                .and_then(|projects| {
                    let sum: f64 = projects
                        .iter()
                        .filter_map(|project| {
                            project
                                .get("breakdown")
                                .and_then(|breakdown| breakdown.get("totalMonthlyCost"))
                                .and_then(Value::as_str)
                                .and_then(|value| value.parse::<f64>().ok())
                        })
                        .sum();
                    (sum > 0.0).then(|| Box::leak(format!("{sum:.2}").into_boxed_str()) as &str)
                })
        });
    counts.total_records = value
        .get("projects")
        .and_then(Value::as_array)
        .map_or(1, Vec::len);
    if let Some(total) = total {
        push_finding(
            findings,
            "infracost.monthly-estimate",
            ExternalSeverity::Info,
            "Estimated monthly infrastructure cost",
            format!("Infracost estimates ${total} per month for the scanned IaC input."),
            None,
        );
    }
}

fn summarize(tool: ExternalTool, value: &Value) -> (ExternalCounts, Vec<ExternalFinding>) {
    let mut counts = ExternalCounts::default();
    let mut findings = Vec::new();
    match tool {
        ExternalTool::Trivy => parse_trivy(value, &mut counts, &mut findings),
        ExternalTool::Checkov => collect_checkov_failed(value, &mut counts, &mut findings),
        ExternalTool::Kubeaudit => collect_kubeaudit(value, &mut counts, &mut findings),
        ExternalTool::Infracost => parse_infracost(value, &mut counts, &mut findings),
        ExternalTool::Prowler
        | ExternalTool::Kubescape
        | ExternalTool::KubeBench
        | ExternalTool::Powerpipe
        | ExternalTool::ScoutSuite => walk_statuses(value, &mut counts, &mut findings),
    }
    if counts.total_records == 0 {
        counts.total_records = counts.passed
            + counts.failed
            + counts.warning
            + counts.skipped
            + counts.informational;
    }
    (counts, findings)
}

fn bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot stat generated report {}: {error}", path.display()))?;
    if metadata.len() > MAX_EXTERNAL_OUTPUT_BYTES as u64 {
        return Err(format!(
            "generated report {} exceeded {MAX_EXTERNAL_OUTPUT_BYTES} byte limit",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read generated report {}: {error}", path.display()))
}

fn find_json_report(directory: &Path) -> Result<PathBuf, String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot inspect generated report directory: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot inspect generated report: {error}"))?;
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json"))
        {
            return Ok(path);
        }
    }
    Err("external tool did not generate a JSON report".to_string())
}

fn provider_label(provider: Option<ExternalProvider>) -> Option<String> {
    provider.map(|provider| format!("{provider:?}").to_ascii_lowercase())
}

/// Run one of the fixed external scanners. The caller cannot provide arbitrary
/// flags or commands. Local targets are constrained to CANONICAL_AUDIT_ROOT.
pub async fn scan(
    tool: ExternalTool,
    provider: Option<ExternalProvider>,
    target: Option<&str>,
    benchmark: Option<&str>,
) -> Result<ExternalScanReport, String> {
    let mut notes = vec![
        "External scanner execution is allowlisted and shell-free; customer-account credentials are inherited from the process environment and must be read-only.".to_string(),
    ];

    let (program, args, generated_dir): (&str, Vec<String>, Option<PathBuf>) = match tool {
        ExternalTool::Prowler => {
            let provider = provider.ok_or_else(|| "prowler requires provider".to_string())?;
            let provider = provider
                .prowler_name()
                .ok_or_else(|| "selected provider is not supported by the Prowler adapter".to_string())?;
            let directory = temporary_report_dir(tool)?;
            let args = vec![
                provider.to_string(),
                "--output-formats".to_string(),
                "json-ocsf".to_string(),
                "--output-directory".to_string(),
                directory.display().to_string(),
                "--output-filename".to_string(),
                "canonical-readiness".to_string(),
            ];
            ("prowler", args, Some(directory))
        }
        ExternalTool::ScoutSuite => {
            let provider = provider.ok_or_else(|| "scout-suite requires provider".to_string())?;
            let provider = provider
                .scout_name()
                .ok_or_else(|| "selected provider is not supported by the ScoutSuite adapter".to_string())?;
            let directory = temporary_report_dir(tool)?;
            let mut args = vec![provider.to_string(), "--no-browser".to_string()];
            if provider == "azure" {
                args.push("--cli".to_string());
            }
            args.push("--report-dir".to_string());
            args.push(directory.display().to_string());
            ("scout", args, Some(directory))
        }
        ExternalTool::Trivy => {
            let target = validated_target(target.ok_or_else(|| "trivy requires target".to_string())?)?;
            (
                "trivy",
                vec![
                    "config".to_string(),
                    "--format".to_string(),
                    "json".to_string(),
                    target.display().to_string(),
                ],
                None,
            )
        }
        ExternalTool::Checkov => {
            let target = validated_target(target.ok_or_else(|| "checkov requires target".to_string())?)?;
            (
                "checkov",
                vec![
                    "-d".to_string(),
                    target.display().to_string(),
                    "-o".to_string(),
                    "json".to_string(),
                    "--compact".to_string(),
                    "--quiet".to_string(),
                ],
                None,
            )
        }
        ExternalTool::Kubescape => {
            let mut args = vec!["scan".to_string()];
            if let Some(target) = target {
                args.push(validated_target(target)?.display().to_string());
            }
            args.extend([
                "--format".to_string(),
                "json".to_string(),
                "--format-version".to_string(),
                "v2".to_string(),
            ]);
            ("kubescape", args, None)
        }
        ExternalTool::KubeBench => (
            "kube-bench",
            vec!["--json".to_string()],
            None,
        ),
        ExternalTool::Kubeaudit => {
            let mut args = vec!["all".to_string(), "--format".to_string(), "json".to_string()];
            if let Some(target) = target {
                args.push("-f".to_string());
                args.push(validated_target(target)?.display().to_string());
            }
            ("kubeaudit", args, None)
        }
        ExternalTool::Infracost => {
            let target = validated_target(target.ok_or_else(|| "infracost requires target".to_string())?)?;
            (
                "infracost",
                vec![
                    "breakdown".to_string(),
                    "--path".to_string(),
                    target.display().to_string(),
                    "--format".to_string(),
                    "json".to_string(),
                ],
                None,
            )
        }
        ExternalTool::Powerpipe => {
            let benchmark = validate_benchmark(
                benchmark.ok_or_else(|| "powerpipe requires benchmark".to_string())?,
            )?;
            (
                "powerpipe",
                vec![
                    "benchmark".to_string(),
                    "run".to_string(),
                    benchmark,
                    "--output".to_string(),
                    "json".to_string(),
                ],
                None,
            )
        }
    };

    let output = run_process(program, &args).await?;
    let mut report = ExternalScanReport {
        tool: tool.as_str(),
        provider: provider_label(provider),
        status: "completed",
        read_only: true,
        executable: program.to_string(),
        arguments: args.clone(),
        exit_code: output.code,
        counts: ExternalCounts::default(),
        findings: Vec::new(),
        notes,
    };

    if !output.stderr.is_empty() {
        report.notes.push(format!(
            "bounded stderr: {}",
            truncate_text(&output.stderr, 1200)
        ));
    }

    if tool == ExternalTool::ScoutSuite {
        let generated = generated_dir
            .as_ref()
            .and_then(|directory| fs::read_dir(directory).ok())
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0);
        report.counts.total_records = generated;
        report.notes.push(format!(
            "ScoutSuite generated {generated} report artifacts. Canonical treats ScoutSuite as an independent cross-check; its HTML/JS report is not returned over MCP."
        ));
    } else {
        let bytes = if let Some(directory) = generated_dir.as_ref() {
            match find_json_report(directory).and_then(|path| bounded_file(&path)) {
                Ok(bytes) => bytes,
                Err(error) if !output.stdout.is_empty() => {
                    report.notes.push(error);
                    output.stdout.clone()
                }
                Err(error) => return Err(error),
            }
        } else {
            output.stdout.clone()
        };
        if !bytes.is_empty() {
            let value = json_or_ndjson(&bytes)?;
            let (counts, findings) = summarize(tool, &value);
            report.counts = counts;
            report.findings = findings;
        }
    }

    if output.code.is_some_and(|code| code != 0) {
        report.status = "completed-with-nonzero-exit";
        report.notes.push(format!(
            "{program} exited non-zero after producing audit evidence; some scanners use non-zero exit codes when findings exist."
        ));
    }
    if report.findings.len() == MAX_FINDINGS {
        report.notes.push(format!(
            "findings were capped at {MAX_FINDINGS}; use the scanner's native report for the complete result set"
        ));
    }

    if let Some(directory) = generated_dir {
        if let Err(error) = fs::remove_dir_all(&directory) {
            report.notes.push(format!(
                "could not remove temporary local report directory {}: {error}",
                directory.display()
            ));
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_contains_independent_security_k8s_and_finops_engines() {
        let names: Vec<_> = catalog().into_iter().map(|tool| tool.tool).collect();
        for expected in [
            "prowler",
            "scout-suite",
            "trivy",
            "checkov",
            "kubescape",
            "kube-bench",
            "kubeaudit",
            "infracost",
            "powerpipe",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        assert!(catalog().iter().all(|profile| !profile.customer_mutations));
    }

    #[test]
    fn benchmark_ids_cannot_inject_flags_or_shell_syntax() {
        assert_eq!(
            validate_benchmark("aws_compliance.benchmark.cis_v400").unwrap(),
            "aws_compliance.benchmark.cis_v400"
        );
        assert!(validate_benchmark("x --output yaml").is_err());
        assert!(validate_benchmark("x;rm").is_err());
        assert!(validate_benchmark("$(whoami)").is_err());
    }

    #[test]
    fn trivy_parser_normalizes_misconfigurations() {
        let value = json!({
            "Results": [{
                "Target": "main.tf",
                "Misconfigurations": [{
                    "ID": "AVD-AWS-0001",
                    "Title": "Bucket is public",
                    "Description": "Public access is enabled",
                    "Severity": "HIGH"
                }]
            }]
        });
        let (counts, findings) = summarize(ExternalTool::Trivy, &value);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.total_records, 1);
        assert_eq!(findings[0].severity, ExternalSeverity::High);
        assert_eq!(findings[0].resource.as_deref(), Some("main.tf"));
    }

    #[test]
    fn checkov_parser_counts_pass_fail_and_skip() {
        let value = json!({
            "results": {
                "passed_checks": [{"check_id":"CKV_OK"}],
                "failed_checks": [{
                    "check_id":"CKV_AWS_1",
                    "check_name":"Encrypt storage",
                    "resource":"aws_s3_bucket.example"
                }],
                "skipped_checks": [{"check_id":"CKV_SKIP"}]
            }
        });
        let (counts, findings) = summarize(ExternalTool::Checkov, &value);
        assert_eq!(counts.passed, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.skipped, 1);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn generic_parser_understands_powerpipe_and_kube_bench_statuses() {
        let value = json!({
            "items": [
                {"status":"ok", "title":"good"},
                {"status":"alarm", "title":"bad", "reason":"needs work"},
                {"status":"skip", "title":"n/a"},
                {"status":"WARN", "test_desc":"manual check"}
            ]
        });
        let (counts, findings) = summarize(ExternalTool::Powerpipe, &value);
        assert_eq!(counts.passed, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.skipped, 1);
        assert_eq!(counts.warning, 1);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ndjson_is_accepted_for_kubeaudit_style_output() {
        let value = json_or_ndjson(
            br#"{"level":"warning","auditResultName":"RunAsRoot","message":"container may run as root","resourceName":"api"}
{"level":"info","message":"ok"}
"#,
        )
        .unwrap();
        let (counts, findings) = summarize(ExternalTool::Kubeaudit, &value);
        assert_eq!(counts.warning, 1);
        assert_eq!(counts.informational, 1);
        assert_eq!(findings.len(), 1);
    }
}
