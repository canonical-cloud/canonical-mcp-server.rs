#!/usr/bin/env sh
set -eu

if [ -z "${CANONICAL_LIB_READ_TOKEN:-}" ]; then
  echo 'CANONICAL_LIB_READ_TOKEN is required for read-only private Canonical Cargo dependencies.' >&2
  exit 1
fi

# Keep the credential process-local. Do not persist it in Git, Cargo config,
# repository files, caches, artifacts, or image layers.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="url.https://x-access-token:${CANONICAL_LIB_READ_TOKEN}@github.com/.insteadOf"
export GIT_CONFIG_VALUE_0="https://github.com/"

exec cargo "$@"
