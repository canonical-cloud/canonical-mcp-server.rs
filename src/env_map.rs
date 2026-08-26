//! Immutable application-environment snapshots.
//!
//! `std::env` is read only at the explicit process boundary. Lower layers
//! operate on ordinary maps, so CLI precedence can be tested without mutating
//! process-global state.

use std::collections::BTreeMap;

pub type EnvMap = BTreeMap<String, String>;

#[must_use]
pub fn merge_env_maps(
    mut base: EnvMap,
    overrides: impl IntoIterator<Item = (String, String)>,
) -> EnvMap {
    base.extend(overrides);
    base
}

#[must_use]
pub fn get_env_map(
    base: EnvMap,
    overrides: impl IntoIterator<Item = (String, String)>,
) -> EnvMap {
    merge_env_maps(base, overrides)
}

#[must_use]
pub fn process_env_map() -> EnvMap {
    std::env::vars().collect()
}

#[must_use]
pub fn value<'a>(env: &'a EnvMap, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_win_without_dropping_unrelated_values() {
        let mut base = EnvMap::new();
        base.insert("HOST".to_owned(), "127.0.0.1".to_owned());
        base.insert("PORT".to_owned(), "3000".to_owned());

        let env = get_env_map(base, [("PORT".to_owned(), "8080".to_owned())]);

        assert_eq!(value(&env, "HOST"), Some("127.0.0.1"));
        assert_eq!(value(&env, "PORT"), Some("8080"));
    }

    #[test]
    fn empty_overrides_preserve_the_base_snapshot() {
        let mut base = EnvMap::new();
        base.insert("MODE".to_owned(), "test".to_owned());

        assert_eq!(get_env_map(base.clone(), std::iter::empty()), base);
    }
}
