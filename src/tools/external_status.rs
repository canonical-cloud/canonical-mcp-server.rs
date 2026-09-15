//! Offline discovery/version checks for optional external readiness engines.
//!
//! Only fixed version/help commands are invoked. No customer credentials,
//! network target, shell, or arbitrary arguments are accepted.

use serde::Serialize;
use std::{process::Stdio, time::Duration};
use tokio::process::Command;

use super::external::ExternalTool;

#[derive(Debug, Serialize)]
pub struct ExternalToolStatus {
    pub tool: &'static str,
    pub executable: &'static str,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub probe: &'static [&'static str],
}

const TOOLS: &[(ExternalTool, &str, &[&str])] = &[
    (ExternalTool::Prowler, "prowler", &["--version"]),
    (ExternalTool::ScoutSuite, "scout", &["--version"]),
    (ExternalTool::Trivy, "trivy", &["--version"]),
    (ExternalTool::Checkov, "checkov", &["--version"]),
    (ExternalTool::Kubescape, "kubescape", &["version"]),
    (ExternalTool::KubeBench, "kube-bench", &["version"]),
    (ExternalTool::Kubeaudit, "kubeaudit", &["version"]),
    (ExternalTool::Infracost, "infracost", &["--version"]),
    (ExternalTool::Powerpipe, "powerpipe", &["--version"]),
];

fn bounded_version(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let normalized = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?
        .chars()
        .take(300)
        .collect::<String>();
    (!normalized.is_empty()).then_some(normalized)
}

async fn probe(
    tool: ExternalTool,
    executable: &'static str,
    args: &'static [&'static str],
) -> ExternalToolStatus {
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(executable)
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;

    let (installed, version) = match result {
        Ok(Ok(output)) => {
            let version =
                bounded_version(&output.stdout).or_else(|| bounded_version(&output.stderr));
            (output.status.success() || version.is_some(), version)
        }
        Ok(Err(_)) | Err(_) => (false, None),
    };

    ExternalToolStatus {
        tool: tool.as_str(),
        executable,
        installed,
        version,
        probe: args,
    }
}

pub async fn status() -> Vec<ExternalToolStatus> {
    let mut statuses = Vec::with_capacity(TOOLS.len());
    for (tool, executable, args) in TOOLS {
        statuses.push(probe(*tool, executable, args).await);
    }
    statuses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_external_tool_has_a_fixed_probe() {
        assert_eq!(TOOLS.len(), 9);
        for (_, executable, args) in TOOLS {
            assert!(!executable.is_empty());
            assert!(!args.is_empty());
            assert!(args
                .iter()
                .all(|arg| !arg.contains(';') && !arg.contains("$(")));
        }
    }

    #[test]
    fn version_output_is_single_line_and_bounded() {
        let version = bounded_version(b"\nProwler 5.25.0\nother\n").unwrap();
        assert_eq!(version, "Prowler 5.25.0");
        assert!(bounded_version(b"\n\n").is_none());
    }
}
