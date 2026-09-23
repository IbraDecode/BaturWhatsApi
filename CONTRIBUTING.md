# Contributing

BaturWhatsApi is an independent, single-team project. Contributions that
respect the project's invariants are welcome.

## Ground rules

1. **Zero third-party deps in core.** See ADR-0002. If you need an
   external package, the canonical answer is to live in an
   optional sibling module (see ADR-0007 for the storage case).
2. **Honest about protocol.** Anything that touches WhatsApp-specific
   shapes must be backed by research (`docs/RESEARCH.md`) or an
   explicit "pending live capture" note in KNOWN_ISSUES. Do not
   invent field numbers or wire shapes.
3. **Tests are part of the change.** Run the full suite locally
   (`go test ./... -count=1 -race -timeout 25m`) before pushing. New
   fuzz targets, regressions from real captures, and conformance
   guards for stable interfaces are all encouraged.
4. **Concurrency story is explicit.** Single-reader for sessions
   (ADR-0003), bounded waits for shutdown (Supervisor.Stop 15 s),
   hijacked WS conns force-closed on shutdown, no naked
   `context.Background()` in library code that can leak.

## Local loop

```sh
make bench                 # or: go run ./cmd/batur bench
make fuzz                  # or run each:
go test -run '^$' -fuzz=FuzzDecodeDefault -fuzztime=10s ./protocol/binary/
go test -run '^$' -fuzz=FuzzParse        -fuzztime=10s ./protocol/pb/
go run ./cmd/batur doctor
go run ./cmd/batur serve --mock --media-demo
```

A useful smoke against your local `serve`:

```sh
python3 examples/sdk/python/batur_client.py --url http://127.0.0.1:8080 ws --seconds 5 --subscribe mock-1
node   examples/sdk/node/batur_client.mjs    --url http://127.0.0.1:8080 ws --seconds 5 --subscribe mock-1
node   examples/sdk/typescript/batur_client.ts --url http://127.0.0.1:8080 ws --seconds 5 --subscribe mock-1
```

## Documentation

Every change that touches user-facing surface updates `docs/API.md`,
`README.md` or `docs/TROUBLESHOOTING.md`. Changes that affect a
backlog row update `docs/TASKS.md`. New design choices go through the
ADR template under `docs/decisions/`.

## Releases

The release workflow (`.github/workflows/release.yml`) builds the
four platform binaries on tag push and attaches them via
`softprops/action-gh-release@v2`. Tag format: `vMAJOR.MINOR.PATCH`.
