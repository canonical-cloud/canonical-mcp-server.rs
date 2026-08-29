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

Only when a human explicitly instructs use of a worktree, place it under `tmp/worktrees/<branch>` `tmp/` is ignored.

## Syncing with the remote

"Sync with the remote" (or just "sync") is a **two-way** exchange — pull the
remote's commits down **and** push yours up. It is never push-only, and a clean
local tree does not by itself mean "synced": you are done only once local and
the remote hold the same commits.

To sync:

1. **Commit your work first** (`git add` + `git commit`) so the tree is clean —
   pull/merge only into a clean tree. `git pull` / `git merge` aborts when an
   incoming change touches a file you have edited, and even when it doesn't it
   buries the merge in your uncommitted work. (Can't commit yet? `git stash`,
   then `git stash pop` after step 3.)
2. `git fetch --all --prune` — safe any time; it only updates tracking refs.
3. `git pull` (fetch + merge) — or `git merge` the upstream branch — to
   integrate the remote's commits.
4. `git push` to publish yours.

Integrate with **`git merge` / `git pull`**. **Never `git rebase` to sync** — it
rewrites history and breaks shared branches.

<!-- ore-primary-branch-policy:begin -->
## Primary branch and concurrent-agent policy

This policy overrides generic feature-branch and worktree defaults for agent tooling.

- Highly prefer an existing primary branch, in this order: `main`, `dev`, then `master`.
- Work directly on the selected primary branch even when other agents are active. Use another branch only when a human or a repository-specific release process explicitly requires it.
- Never create or use a Git worktree unless a human explicitly instructs you to do so for the current task. Concurrency alone is not permission to use a worktree.
- Concurrent agents must coordinate repository and file ownership through the available agent communication channel, keep edits scoped, inspect live state before each write, and hand off cleanly. Coordinate instead of isolating routine work in worktrees.
- Preserve unrelated in-progress changes and never overwrite another agent's work. If safe ownership of overlapping files cannot be established, pause that overlapping edit and coordinate before continuing.
<!-- ore-primary-branch-policy:end -->
