#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
telemetry = root / "src" / "telemetry.rs"
text = telemetry.read_text(encoding="utf-8")
old = '''pub fn init(service_name: &'static str, service_namespace: &'static str) -> TelemetryGuard {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,hyper=warn"));
    let resource = resource(service_name, service_namespace);
'''
new = '''pub fn init(
    service_name: &'static str,
    service_namespace: &'static str,
    filter: EnvFilter,
) -> TelemetryGuard {
    let resource = resource(service_name, service_namespace);
'''
if text.count(old) != 1:
    raise SystemExit("telemetry init marker mismatch")
telemetry.write_text(text.replace(old, new, 1), encoding="utf-8")

readme = root / "README.md"
text = readme.read_text(encoding="utf-8")
old = '''```sh
cargo run
```

The server speaks MCP over stdin/stdout; it is meant to be launched by an MCP
client, not used interactively.
'''
new = '''```sh
cargo run
cargo run -- --log-filter=debug,hyper=warn
```

The binary audits `.cli-flags.toml` before telemetry or MCP startup. Set
`CANONICAL_FLAGS_CONFIG` when an installed binary cannot discover the contract
from the current directory, executable directory, or `../share/canonical-mcp-server`.
Only the non-secret log filter is accepted as a flag.

The server speaks MCP over stdin/stdout; it is meant to be launched by an MCP
client, not used interactively.
'''
if text.count(old) != 1:
    raise SystemExit("README running marker mismatch")
readme.write_text(text.replace(old, new, 1), encoding="utf-8")
