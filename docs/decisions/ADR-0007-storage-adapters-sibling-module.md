# ADR-0007 — Storage adapters live in an optional sibling module

Date: 2026-09-23
Status: Accepted

## Context

ADR-0004 chose a file-backed KV as the default persistence. The backlog
(P2) lists Postgres/SQLite adapters so multi-node active-active
deployments become viable. Both database engines require a Go driver
(`github.com/lib/pq` / `jackc/pgx` / `mattn/go-sqlite3` / `modernc.org/sqlite`).

ADR-0002 forbids third-party imports in the **core** module. It was never
meant to block optional integrations entirely — but a Postgres driver
sitting in the main `go.mod` would break the auditability story
(reviewers see driver surface every time they review protocol code) and
unnecessarily penalize users who never enable the adapter.

## Decision

Postgres / SQLite adapters live in a **separate Go module**:

```
github.com/ibradecode/baturwhatsapi/storage-adapters
```

- Own `go.mod` declaring the chosen driver dependencies.
- Imports the core (`storage.KV` interface + `Batur.Options.Store` is
  already an interface seam) and registers a constructor that satisfies
  it.
- Wire-up at the call site is one line:

  ```go
  import (
      "github.com/ibradecode/baturwhatsapi/storage"
      storeadapters "github.com/ibradecode/baturwhatsapi/storage-adapters/postgres"
  )
  ...
  opts.Store = storeadapters.NewPostgres(dsn)
  ```

- The core repo keeps one CI lane (current zero-dep `go test ./...`)
  and adds a second CI lane `storage-adapters/` with the drivers
  enabled, so the adapter path is exercised without polluting the
  primary module.

## Consequences

- ADR-0002 stays strict: `go.mod` of the core has no third-party
  requires.
- Adapter consumers opt in explicitly by importing the sibling module;
  they accept the supply-chain surface they bring in.
- The `storage.KV` interface is the only contract that must remain
  stable. Any future field added to it is a breaking change for every
  adapter and is treated as such.
- The file store remains the default and the deployment unit; the
  adapters are an integration point, not a productized feature yet.
