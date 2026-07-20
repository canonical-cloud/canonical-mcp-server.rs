# Agent guidelines — canonical-mcp-server.rs

Rust MCP (Model Context Protocol) stdio server for operating the
**canonical.cloud** stack (GitHub org `canonical-cloud`). Built on the official
`rmcp` SDK, tokio, and reqwest (rustls). Developer/ops tooling only — it is
never deployed and binds no ports.

## Layout

- `src/main.rs` — bootstrap only.
- `src/server.rs` — tool router, parameter schemas, `ServerHandler`.
- `src/tools/github.rs` — GitHub API client and pure JSON summarization.
- `src/tools/health.rs` — health-endpoint probing and truncation.
- `src/tools/docs.rs` — monorepo doc fetching plus the embedded `org-map`
  knowledge doc.
- `src/tools/domain.rs` — RDAP + DNS-over-HTTPS domain reporting.
- `src/tools/cloudflare.rs` — read-only Cloudflare zone/record listing.
- `src/tools/k8s.rs` — allowlisted `kubectl get` runner and summarizers.
- `src/tools/fiducia.rs` — read-only fiducia.cloud secret-presence and
  lock/lease health check.

## Working here

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## Invariants

- stdout belongs to the MCP protocol. Never print to stdout; diagnostics go to
  stderr if anywhere.
- Tests never touch the network. Keep response interpretation in pure
  functions over `serde_json::Value`/`&str` fixtures; confine I/O to the thin
  client and orchestration functions.
- Tools stay read-only against GitHub, Cloudflare, Kubernetes, fiducia.cloud,
  and deployments. Adding a mutating tool is a design change, not a patch.
- `k8s.rs` may only ever build `kubectl get` (and `kubectl config
  get-contexts`) argument vectors — never exec/delete/apply, and never via a
  shell.
- Never log or echo tokens: the GitHub token goes only to `api.github.com`,
  the Cloudflare token only to `api.cloudflare.com`, and the fiducia token
  only to `FIDUCIA_URL`. `fiducia.rs` fetches secret *presence*, never
  secret values.
- Truncate and bound anything returned from remote services.

## Command safety

Agents working in this repo must **not** run destructive shell commands.

**Blacklisted (never run):** `rm`, `rm -rf`, `rmdir`, `dd`, `mkfs`, `shred`,
`truncate`, `> file` truncation, `find … -delete`, `git clean -fdx`,
`git reset --hard` on shared branches, `git push --force` to `main`, and any
`sudo`-prefixed or disk/format command.

**Whitelisted (prefer these):** `git rm` and `git mv` for tracked removals and
moves, `git restore` / `git revert` to undo, and files under ignored
`tmp/worktrees/` for scratch work. Let a human review staged removals.

## Git worktrees

Create worktrees only under `tmp/worktrees/<branch>`; `tmp/` is ignored.

## Syncing with the remote

"Sync with the remote" (or just "sync") is **bidirectional and always contacts
the remote** — it fetches *and* pushes, never push-only. A clean local working
tree does **not** by itself mean "synced": a sync is not finished until local
and the remote have exchanged commits in both directions.

How to sync:

1. `git fetch --all --prune` — always safe; it only updates remote-tracking
   refs and never touches your working tree, so run it any time.
2. Make the working tree **clean before you pull/merge**: `git add` +
   `git commit` your work (or `git stash`). **Only `git pull` / `git merge`
   when the tree is not dirty** — pulling into a dirty tree makes git refuse
   the merge or tangle uncommitted edits with the incoming commits.
3. `git pull` (which fetches + merges) — or `git merge` the upstream tracking
   branch — to integrate the remote's commits into your now-clean branch.
4. `git push` — publish your commits so the remote has them too.

Integrate with **`git merge`** / **`git pull`** (which merges). **Never
`git rebase`** to sync — it rewrites history and breaks shared branches.
