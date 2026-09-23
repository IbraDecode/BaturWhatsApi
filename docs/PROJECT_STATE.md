# PROJECT STATE — BaturWhatsApi

Updated: 2026-09-23 · Engine: v0.1.1 (development channel) · Branch: `main` · Release: [v0.1.1](https://github.com/IbraDecode/BaturWhatsApi/releases/tag/v0.1.1)

## Snapshot

BaturWhatsApi is an **independent WhatsApp-Web communication engine**
(library + platform), not a wrapper of any existing implementation.
Reference projects (Baileys, whatsmeow, GOWA, wa-go, wa-spec) were used
**only as protocol research**.

Core principle: a persistent, resilient, modular, multi-session,
low-memory, observable, production-grade engine — and a runtime that is
itself 24/7 (supervisor + automatic recovery).

## Production-readiness gate

| Area                 | Status | Evidence |
|----------------------|--------|----------|
| Architecture         | ✅     | `docs/architecture/ARCHITECTURE.md`, 5 ADRs |
| Protocol layer       | ✅     | WAWebMulti binary node codec + dictionaries + zlib + pb wire subset; fuzz round-trip (500 cases) |
| Security layer       | ✅     | Noise_XX_25519_AESGCM_SHA256 (WhatsApp variant), AES-256-GCM ctr ciphers, HKDF RFC 5869 vectors, CertChain Ed25519 verification (wacert), fail-closed auth, **AES-256-GCM sealed storage** |
| Transport            | ✅     | RFC 6455 WS client (masked, fragmented, ping/pong, size limits) + in-memory pipe |
| Session engine       | ✅     | full lifecycle, request/response matching, keepalive, stale detection, single-reader concurrency contract |
| State machine        | ✅     | 10 explicit states, legal-transition enforcement, watchers, forced-recovery path |
| Multi-session        | ✅     | isolated per-session state; 3-session stress test with unique noise keys |
| Persistence          | ✅     | KV abstraction; memory + file stores; resume-across-restart integration test |
| Supervisor (24/7)    | ✅     | backoff + jitter, stability reset, stuck watchdog, chaos-reconnect test |
| Events               | ✅     | ordered bus, block/drop policies, panic isolation, wildcard routing |
| Public API           | ✅     | façade + domain models + subscriptions + **SendText wired end-to-end** (engine-to-engine via mock relay) |
| E2E crypto (Signal)  | 🟡     | X3DH + Double Ratchet + state persistence DONE (security/e2e, race-clean); WhatsApp SignalMessage wire mapping = T-102 |
| Sync engine          | ✅     | resumable stages + snapshot store + auto-sync-on-ready + periodic refresh + REST (/sync,/contacts,/chats) + Prometheus; protocol-verified |
| Media engine         | ❌     | Phase 3 |
| Observability        | ✅     | /metrics Prometheus (session state one-hot, retries, online, heap/goroutine/gc, bus counters), structured logs, health API |
| REST/WS API server   | ✅     | apiserver v1: REST + SSE + **WebSocket event bridge** (send/sync/subscribe, bearer auth, /metrics gauge) + sealed storage; pairing endpoints pending |
| Testing              | ✅     | 12/12 packages green incl. stress + chaos tests; `-race` full suite CLEAN |
| Benchmarks           | ✅     | `internal/bench`: 100 idle sessions = 119.8 KiB heap/session, ~5 goroutines/session, 52.7K encrypted IQ round-trips/s single session (19µs/op); node codec 2.2µs enc / 3.2µs dec; race + stress green |
| CI/CD                | ✅     | GitHub Actions: build, vet, fuzz-smoke tests, race, cross-compile |
| Deployment           | 🟡     | single-binary model; Dockerfile pending |
| Security audit       | 🟡     | in progress (see KNOWN_ISSUES) |

## Key runtime facts (this machine, constrained container)

- Go 1.27.1 (installed to `~/.local/go`), GOFLAGS: none, CGO off.
- Memory 2GB — engine idle RSS target < 20MB/session remains plausible
  (no measurements yet; benchmark task queued).
- Full test suite ~3s; `-race` green across all 17 packages incl. the
  API/SSE/sync integration tests (2026-09-23).

## Repository layout (current)

```
api/          public façade (Batur, Status, subscriptions, Message model)
cmd/batur/    CLI (version | doctor | bench | demo)
events/       event bus
internal/     mockserver (protocol-level test/demo server), wapb, version
protocol/     binary (WAWebMulti codec), pb (protobuf wire), token (dicts)
security/     hkdf (RFC 5869), noise (XX handshake + transport ciphers)
session/      connection engine per device
statemachine/ connection lifecycle FSM
storage/      KV interface + memory + file
supervisor/   fleet supervision + recovery loops
transport/    Conn/Dialer contracts, pipe, ws (RFC 6455)
docs/         architecture, ADRs, research, ops notes (this folder)
```

## How to run

```
make test          # all packages
make race          # race detector (slower)
make bench         # micro-benchmarks
go run ./cmd/batur demo     # full in-process end-to-end (mock server)
go run ./cmd/batur doctor   # engine self-check
```

## Session memory for AI contributors

This file + `TASKS.md` + `KNOWN_ISSUES.md` are the durable project
brain. On every significant change, update all three. If a task is done
but untested, it is NOT done.
