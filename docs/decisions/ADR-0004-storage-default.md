# ADR-0004 — File-backed KV is the default persistence

Date: 2026-09-23
Status: Accepted

## Context

Sessions must survive process restarts (credentials, server-static pins,
sync checkpoints). Candidates: embedded SQLite, PostgreSQL, file KV.

## Decision

Default storage is a **directory-based KV** (`storage.NewFileStore`) with
manifest indexing, atomic writes (temp+rename), traversal-safe keys, and
0700/0600 permissions. PostgreSQL/SQLite adapters plug into the same
`storage.KV` interface later (they arrive with the sync engine).

## Consequences

- Zero deps, one binary + a data dir: simplest possible 24/7 deployment.
- Not suitable for multi-node active-active — that is exactly what the
  PostgreSQL adapter (backlog P2) will solve.
- Atomic rename-based writes leave crash-tolerant state; fsync of the
  directory entry is a hardening task.
