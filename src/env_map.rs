//! Immutable application environment snapshots.

use std::collections::BTreeMap;

pub type EnvMap = BTreeMap<String, String>;

/// Return a new map where later override values win over the initial snapshot.
pub fn get_env_map(
    mut initial: EnvMap,
    overrides: impl IntoIterator<Item = (String, String)>,
) -> EnvMap {
    initial.extend(overrides);
    initial
}

pub fn process_env_map() -> EnvMap {
    std::env::vars().collect()
}

pub fn process_argv() -> Vec<String> {
    std::env::args().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_values_win_without_mutating_the_captured_base() {
        let base = EnvMap::from([
            ("RUST_LOG".to_owned(), "info".to_owned()),
            ("CANONICAL_REGION".to_owned(), "iad".to_owned()),
        ]);
        let untouched = base.clone();
        let merged = get_env_map(base, [("RUST_LOG".to_owned(), "debug".to_owned())]);

        assert_eq!(merged["RUST_LOG"], "debug");
        assert_eq!(merged["CANONICAL_REGION"], "iad");
        assert_eq!(untouched["RUST_LOG"], "info");
    }
}
