#!/usr/bin/env python3
from dataclasses import dataclass
from collections import deque

READ, WRITE, ADMIN = "read", "write", "admin"

@dataclass(frozen=True)
class State:
    tenant_ctx: bool = False
    authn: bool = False
    admin_ctx: bool = False
    mutated: bool = False
    executed_read: bool = False
    executed_write: bool = False
    executed_admin: bool = False


def next_states(s: State):
    out = []
    if not s.tenant_ctx:
        out.append(State(True, s.authn, s.admin_ctx, s.mutated, s.executed_read, s.executed_write, s.executed_admin))
    if not s.authn:
        out.append(State(s.tenant_ctx, True, s.admin_ctx, s.mutated, s.executed_read, s.executed_write, s.executed_admin))
    if s.authn and not s.admin_ctx:
        out.append(State(s.tenant_ctx, True, True, s.mutated, s.executed_read, s.executed_write, s.executed_admin))
    if s.tenant_ctx and s.authn and not s.executed_read:
        out.append(State(s.tenant_ctx, s.authn, s.admin_ctx, s.mutated, True, s.executed_write, s.executed_admin))
    if s.tenant_ctx and s.authn and not s.executed_write:
        out.append(State(s.tenant_ctx, s.authn, s.admin_ctx, True, s.executed_read, True, s.executed_admin))
    if s.tenant_ctx and s.authn and s.admin_ctx and not s.executed_admin:
        out.append(State(s.tenant_ctx, s.authn, s.admin_ctx, True, s.executed_read, s.executed_write, True))
    return out


def check(s: State):
    if s.executed_read or s.executed_write or s.executed_admin:
        assert s.tenant_ctx and s.authn, "tool execution without authenticated tenant context"
    if s.executed_admin:
        assert s.admin_ctx, "admin tool executed without admin context"
    if s.executed_read and not (s.executed_write or s.executed_admin):
        assert not s.mutated, "read-only tool mutated state"
    if s.mutated:
        assert s.executed_write or s.executed_admin, "mutation without a write-capable tool"


def main():
    start = State()
    q = deque([start]); seen = {start}; edges = 0
    while q:
        s = q.popleft(); check(s)
        for n in next_states(s):
            edges += 1; check(n)
            if n not in seen:
                seen.add(n); q.append(n)
    assert any(s.executed_admin for s in seen)
    print(f"MCP authority model: {len(seen)} states, {edges} transitions")

if __name__ == "__main__":
    main()
