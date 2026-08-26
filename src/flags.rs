//! Strict, stdio-safe flags2env startup configuration.
//!
//! CLI values are validated into an ordinary `EnvMap`; the process environment
//! is copied once at bootstrap and is never mutated.

use std::{
    error::Error,
    io,
    path::{Path, PathBuf},
};

use flags2env::BundledFlags2Env;
use tracing_subscriber::EnvFilter;

use crate::env_map::{
    EnvMap, get_env_map, process_argv, process_env_map as capture_process_env,
};

const RUST_LOG: &str = "RUST_LOG";
const DEFAULT_LOG_FILTER: &str = "info,hyper=warn";
const MAX_LOG_FILTER_BYTES: usize = 4_096;

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Parse CLI arguments into an immutable environment override value.
pub fn parse_cli_overrides(
    argv: &[String],
    config_path: &Path,
) -> Result<EnvMap, Box<dyn Error>> {
    let config_path = config_path
        .to_str()
        .ok_or_else(|| invalid_input(".cli-flags.toml path is not valid UTF-8"))?;
    let parser = BundledFlags2Env::new();
    parser.audit_config(Some(config_path)).map_err(|error| {
        invalid_input(format!("flags-2-env configuration audit failed: {error}"))
    })?;
    let parsed = parser
        .parse_structured(argv, Some(config_path))
        .map_err(|error| invalid_input(format!("flags-2-env parse failed: {error}")))?;

    if !parsed.unknown_options.is_empty() {
        return Err(invalid_input(format!(
            "unknown command-line option(s): {}",
            parsed.unknown_options.join(", ")
        ))
        .into());
    }
    if !parsed.errors.is_empty() {
        return Err(invalid_input(format!(
            "invalid command-line value(s): {}",
            parsed.errors.join("; ")
        ))
        .into());
    }
    if !parsed.extras.is_empty() {
        return Err(invalid_input(format!(
            "unexpected positional argument(s): {}",
            parsed.extras.join(", ")
        ))
        .into());
    }
    for (key, value) in &parsed.flags {
        if key != RUST_LOG {
            return Err(invalid_input(format!(
                "unsupported CLI environment override: {key}"
            ))
            .into());
        }
        if value.len() > MAX_LOG_FILTER_BYTES || value.chars().any(char::is_control) {
            return Err(invalid_input("CLI log filter is invalid or too large").into());
        }
    }

    Ok(parsed.flags.into_iter().collect())
}

pub fn log_filter(env: &EnvMap) -> Result<EnvFilter, Box<dyn Error>> {
    let filter = env
        .get(RUST_LOG)
        .map(String::as_str)
        .unwrap_or(DEFAULT_LOG_FILTER);
    EnvFilter::try_new(filter)
        .map_err(|error| invalid_input(format!("invalid --log-filter value: {error}")))
        .map_err(Into::into)
}

/// Compatibility helper for deterministic parser tests and existing callers.
pub fn parse_cli_flags(argv: &[String], config_path: &Path) -> Result<EnvFilter, Box<dyn Error>> {
    let overrides = parse_cli_overrides(argv, config_path)?;
    log_filter(&get_env_map(EnvMap::new(), overrides))
}

pub fn resolve_config_path() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = std::env::var_os("CANONICAL_FLAGS_CONFIG").filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(
            invalid_input("CANONICAL_FLAGS_CONFIG does not point to a readable file").into(),
        );
    }

    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join(".cli-flags.toml"));
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            candidates.push(parent.join(".cli-flags.toml"));
            candidates.push(parent.join("../share/canonical-mcp-server/.cli-flags.toml"));
        }
    }

    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            invalid_input("cannot locate .cli-flags.toml; set CANONICAL_FLAGS_CONFIG to its path")
                .into()
        })
}

pub fn process_env_map() -> Result<EnvMap, Box<dyn Error>> {
    let config_path = resolve_config_path()?;
    let argv = process_argv();
    let overrides = parse_cli_overrides(&argv, &config_path)?;
    Ok(get_env_map(capture_process_env(), overrides))
}

pub fn process_log_filter() -> Result<EnvFilter, Box<dyn Error>> {
    log_filter(&process_env_map()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".cli-flags.toml")
    }

    #[test]
    fn accepts_only_the_declared_stderr_log_filter() {
        let argv = vec![
            "canonical-mcp-server".to_owned(),
            "--log-filter=debug,hyper=warn".to_owned(),
        ];
        let filter = parse_cli_flags(&argv, &config_path()).expect("valid operational flag");
        assert!(filter.to_string().contains("debug"));
    }

    #[test]
    fn rejects_secret_bearing_flags() {
        let argv = vec![
            "canonical-mcp-server".to_owned(),
            "--fiducia-token=must-remain-environment-only".to_owned(),
        ];
        let error = parse_cli_flags(&argv, &config_path())
            .expect_err("secret-bearing option must remain unknown")
            .to_string();
        assert!(error.contains("unknown command-line option"));
    }

    #[test]
    fn rejects_invalid_log_filters() {
        let argv = vec![
            "canonical-mcp-server".to_owned(),
            "--log-filter=[invalid".to_owned(),
        ];
        assert!(parse_cli_flags(&argv, &config_path()).is_err());
    }

    #[test]
    fn derives_the_filter_from_the_merged_environment_value() {
        let env = EnvMap::from([(RUST_LOG.to_owned(), "warn,hyper=error".to_owned())]);
        assert!(log_filter(&env).unwrap().to_string().contains("warn"));
    }
}
