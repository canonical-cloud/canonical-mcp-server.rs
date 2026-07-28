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
fn tool_implementations_do_not_depend_on_server_framework_types() {
    for path in all_sources()
        .into_iter()
        .filter(|path| path.starts_with(repository_root().join("src/tools")))
    {
        let body = source(relative(&path));
        for framework_marker in [
            "ServerHandler",
            "ServerCapabilities",
            "ToolRouter",
            "#[tool_router]",
            "#[tool_handler]",
        ] {
            assert!(
                !body.contains(framework_marker),
                "{} contains server framework concern {framework_marker}",
                relative(&path).display()
            );
        }
    }
}

#[test]
fn kubernetes_adapter_stays_allowlisted_and_shell_free() {
    let sources = all_sources();
    let command_owners = files_containing(&sources, "Command::new");
    assert_eq!(command_owners.len(), 1, "process spawning gained a new owner");
    assert_eq!(relative(command_owners[0]), Path::new("src/tools/k8s.rs"));

    let k8s = source("src/tools/k8s.rs");
    assert!(k8s.contains("Command::new(\"kubectl\")"));
    assert!(!k8s.contains("sh -c"));
    assert!(!k8s.contains("bash -c"));
}

#[test]
fn process_side_effects_have_single_module_owners() {
    let sources = all_sources();
    assert_eq!(
        files_containing(&sources, "std::env::var(")
            .into_iter()
            .map(|path| relative(path))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            PathBuf::from("src/flags.rs"),
            PathBuf::from("src/telemetry.rs"),
            PathBuf::from("src/tools/cloudflare.rs"),
            PathBuf::from("src/tools/fiducia.rs"),
            PathBuf::from("src/tools/github.rs"),
        ])
    );
}

#[test]
fn stdout_is_reserved_for_the_mcp_protocol() {
    let sources = all_sources();
    for macro_name in ["print", "println"] {
        let owners = files_invoking_macro(&sources, macro_name);
        assert!(
            owners.is_empty(),
            "{macro_name}! writes to stdout from {:?}",
            owners
                .into_iter()
                .map(|path| relative(path))
                .collect::<Vec<_>>()
        );
    }
}
