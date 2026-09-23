# Development guide

## Environment

- Go ≥ 1.23 (developed on 1.27). No CGO, no external services.
- `make test` ~2s · `make race` minutes on small CPUs.

## Conventions (hard rules for every contributor, human or AI)

1. **No third-party imports** in the core (ADR-0002). Stdlib only.
2. One reader per `transport.Conn` (ADR-0003). New sockets get their own
   task loop.
3. Protocol objects (`binary.Node`, raw attrs) never appear in `api`
   handler signatures — translate to domain models.
4. Every bug fix ships with a regression test (name the bug in the test
   doc-comment).
5. Update `docs/PROJECT_STATE.md`, `docs/TASKS.md`,
   `docs/KNOWN_ISSUES.md` in the same commit as functional changes.
6. Tests must not assume wall-clock < 50ms timings on CI; use generous
   deadlines + explicit signals (channels), never sleep-race the stack.
7. gofmt clean; `go vet` clean; zero panics in production paths
   (encoders return errors; tests may use panicking helpers).

## Testing map

| Package | Focus |
|---------|-------|
| protocol/binary | round-trip fuzz, dictionary/pack flavors, truncation |
| protocol/pb | known-answer wire vectors |
| security/hkdf | RFC 5869 official vectors |
| security/noise | handshake/tamper/binding/counter monotonicity |
| transport/ws | RFC 6455 loopback: handshake, fragmentation, ping/pong, length forms |
| events | ordering, backpressure, drop policy, panic isolation |
| statemachine | legal/illegal edges, watchers, force path |
| storage | KV contract shared suite + persistence + traversal safety |
| session | lifecycle, resume, fail-closed auth, stale recovery, connect-cycle stress |
| supervisor | chaos reconnect, multi-session isolation |

## Adding a subsystem

1. Research notes → `docs/RESEARCH.md`.
2. Interface first (small, documented), then implementation, then
   failure tests, then wire into `api`.
3. ADR when the design could plausibly have been different.
