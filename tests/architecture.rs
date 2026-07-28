use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source(path: impl AsRef<Path>) -> String {
    let path = repository_root().join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn rust_sources_below(path: &Path, sources: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    }) {
        let entry = entry.expect("source directory entry must be readable");
        let path = entry.path();
        if path.is_dir() {
            rust_sources_below(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

fn all_sources() -> Vec<PathBuf> {
    let mut sources = Vec::new();
    rust_sources_below(&repository_root().join("src"), &mut sources);
    sources
}

fn files_containing<'a>(sources: &'a [PathBuf], marker: &str) -> Vec<&'a PathBuf> {
    sources
        .iter()
        .filter(|path| {
            fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
                .contains(marker)
        })
        .collect()
}

fn files_invoking_macro<'a>(sources: &'a [PathBuf], macro_name: &str) -> Vec<&'a PathBuf> {
    let marker = format!("{macro_name}!(");
    sources
        .iter()
        .filter(|path| {
            let body = fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            body.match_indices(&marker).any(|(index, _)| {
                index == 0
                    || body[..index].chars().next_back().is_none_or(|character| {
                        !character.is_ascii_alphanumeric() && character != '_'
                    })
            })
        })
        .collect()
}

fn relative(path: &Path) -> PathBuf {
    path.strip_prefix(repository_root())
        .expect("source must be inside repository")
        .to_path_buf()
}

#[test]
fn main_remains_a_thin_declarative_bootstrap() {
    let main = source("src/main.rs");
    let module_declarations = main
        .lines()
        .filter_map(|line| line.trim().strip_prefix("mod "))
        .filter_map(|module| module.strip_suffix(';'))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        module_declarations,
        BTreeSet::from(["flags", "server", "telemetry", "tools"])
    );
    assert!(main.contains("flags::process_log_filter()?"));
    assert!(main.contains("telemetry::init("));
    assert!(main.contains("server::CanonicalMcp::new()?"));
    assert!(main.contains(".serve(stdio())"));
    assert!(
        main.lines().filter(|line| !line.trim().is_empty()).count() <= 24,
        "main.rs accumulated application logic"
    );

    for leaked_concern in [
        "reqwest::",
        "Command::new",
        "tool_router!",
        "serde_json::",
        "kubectl",
    ] {
        assert!(
            !main.contains(leaked_concern),
            "main.rs owns non-bootstrap concern {leaked_concern}"
        );
    }
}

#[test]
fn every_tool_file_is_registered_once() {
    let tools_dir = repository_root().join("src/tools");
    let files = fs::read_dir(&tools_dir)
        .expect("tools directory must be readable")
        .map(|entry| entry.expect("tool entry must be readable").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| *stem != "mod")
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    let registry = source("src/tools/mod.rs")
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub mod "))
        .filter_map(|module| module.strip_suffix(';'))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    assert_eq!(registry, files, "tool module registry drifted from files");
    assert_eq!(registry.len(), 7, "unexpected tool surface change");
}

#[test]
fn process_side_effects_have_single_module_owners() {
    let sources = all_sources();
    let ownership = [
        (".serve(stdio())", "src/main.rs"),
        ("reqwest::Client::builder", "src/server.rs"),
        (
            "tokio::process::Command::new(\"kubectl\")",
            "src/tools/k8s.rs",
        ),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "src/telemetry.rs"),
    ];

    for (marker, expected_owner) in ownership {
        let owners = files_containing(&sources, marker);
        assert_eq!(
            owners.len(),
            1,
            "{marker} must have exactly one module owner"
        );
        assert_eq!(relative(owners[0]), PathBuf::from(expected_owner));
    }
}

#[test]
fn stdout_is_reserved_for_the_mcp_protocol() {
    let sources = all_sources();
    assert!(
        files_invoking_macro(&sources, "println").is_empty(),
        "println! can corrupt stdio JSON-RPC framing"
    );
    assert!(
        files_invoking_macro(&sources, "print").is_empty(),
        "print! can corrupt stdio JSON-RPC framing"
    );

    let stderr_owners = files_containing(&sources, "eprintln!(");
    assert_eq!(stderr_owners.len(), 1);
    assert_eq!(
        relative(stderr_owners[0]),
        PathBuf::from("src/telemetry.rs")
    );
}

#[test]
fn tool_implementations_do_not_depend_on_server_framework_types() {
    let tools_dir = repository_root().join("src/tools");
    let mut tool_sources = Vec::new();
    rust_sources_below(&tools_dir, &mut tool_sources);

    for path in tool_sources {
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for framework_type in ["CanonicalMcp", "ToolRouter", "ServerHandler"] {
            assert!(
                !body.contains(framework_type),
                "{} depends on server framework type {framework_type}",
                relative(&path).display()
            );
        }
    }

    let server = source("src/server.rs");
    assert!(server
        .contains("use crate::tools::{cloudflare, docs, domain, fiducia, github, health, k8s};"));
    assert!(!server.contains("tokio::process::Command"));
}

#[test]
fn kubernetes_adapter_stays_allowlisted_and_shell_free() {
    let k8s = source("src/tools/k8s.rs");
    assert!(k8s.contains("tokio::process::Command::new(\"kubectl\")"));
    assert!(k8s.contains("\"get\".to_string()"));
    assert!(k8s.contains("\"--request-timeout=15s\".to_string()"));
    assert!(k8s.contains("validate_k8s_name(namespace, \"namespace\")?"));
    assert!(k8s.contains("validate_k8s_name(context, \"context\")?"));

    for forbidden in [
        "Command::new(\"sh\")",
        "Command::new(\"bash\")",
        "\"delete\".to_string()",
        "\"apply\".to_string()",
        "\"exec\".to_string()",
    ] {
        assert!(
            !k8s.contains(forbidden),
            "Kubernetes adapter gained forbidden command surface {forbidden}"
        );
    }
}
