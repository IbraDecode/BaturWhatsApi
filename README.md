# BaturWhatsApi

**Independent WhatsApp Web communication engine** — persistent,
resilient, modular, multi-session, low-memory, observable, production
in progress. Not a wrapper. Own protocol codec, own security layer, own
session & supervisor runtime, own public API.

```
Application
    ↓
Public API / SDK          (api/, later REST + WebSocket servers)
    ↓
Domain Engine             (domain models, event translation)
    ↓
Session Engine            (session/, one connection per device)
    ↓
Protocol Engine           (protocol/: WAWebMulti nodes, dictionaries, pb wire)
    ↓
Security Engine           (security/: Noise XX + AES-256-GCM + HKDF)
    ↓
Transport                 (transport/: RFC 6455 client, pipe)
```

Supporting systems: storage abstraction, event bus, supervisor (24/7
recovery), state machine, observability.

## Status (v0.1.0)

Core runtime is alive end-to-end: dial → noise handshake (verified
cert-chain) → binary protocol → encrypted node exchange → events →
multi-session supervision with automatic recovery, sessions survive
restarts. Engine-to-engine **end-to-end encrypted messaging** (X3DH +
Double Ratchet, stdlib-only) and a **resumable sync framework** are in.
See `docs/PROJECT_STATE.md` for the honest readiness matrix; the next
milestone is WhatsApp wire-compatibility mapping (docs/TASKS.md T-102).

## Quickstart

Requires Go ≥ 1.23.

```bash
make test        # full suite
make race        # race detector (slow CPU container: may take minutes)
make bench       # codec / crypto micro-benchmarks

# run the whole engine in one process (mock WhatsApp-web server):
go run ./cmd/batur demo
go run ./cmd/batur doctor            # runtime + crypto + engine + e2e self-check
go run ./cmd/batur doctor --json      # machine-readable single JSON object
go run ./cmd/batur serve --mock --bind 127.0.0.1:8080   # REST + SSE API
go run ./cmd/batur serve --mock --media-demo             # additionally pushes an image message
```

## Embedding (library mode)

```go
import (
    "github.com/ibradecode/baturwhatsapi/api"
    "github.com/ibradecode/baturwhatsapi/session"
)

b, _ := api.New(api.Options{})
b.Attach("device-a", myDialer, myServerAuthPolicy,
    session.DeviceInfo{Platform: "web", DeviceName: "my-app"})
b.Bus().MustSubscribe("message.*", 256, 0, func(ctx context.Context, ev events.Event) {
    fmt.Println("message event:", ev.Session)
})
b.Start(ctx)
```

## HTTP API (v1 bridge)

```
GET  /v1/health                     engine + bus stats (public)
GET  /v1/sessions                   fleet health
GET  /v1/sessions/{id}              one session
DELETE /v1/sessions/{id}            detach
POST /v1/sessions/{id}/iq           raw protocol bridge
POST /v1/sessions/{id}/text         encrypted send (when a bundle source is wired)
POST /v1/sessions/{id}/sync         resumable contacts/chats sync
GET  /v1/sessions/{id}/contacts     synced contacts snapshot
GET  /v1/sessions/{id}/chats        synced chats snapshot
GET  /v1/sessions/{id}/history      bounded per-chat message history (?chat=&limit=)
GET  /v1/events                     Server-Sent Events (all types)
GET  /v1/ws                         WebSocket event bridge (JSON frames; send/sync/subscribe commands)
GET  /metrics                       Prometheus text endpoint
Authorization: Bearer $BATUR_API_TOKEN   (required for non-local bind)
```

Zero-dependency SDK examples that speak the REST + WS API live in
`examples/sdk/`. Each ships the same six subcommands:

| subcommand  | what it does                              |
|-------------|-------------------------------------------|
| `health`    | GET /v1/health (public)                   |
| `sessions`  | GET /v1/sessions                          |
| `get`       | GET /v1/sessions/{id}                     |
| `text`      | POST /v1/sessions/{id}/text (sid to text) |
| `events`    | GET /v1/events (SSE, optional seconds)    |
| `ws`        | GET /v1/ws (live frames, optional seconds; `--subscribe` for session filter; TS/Python only: jid filter on `subscribe`) |

Quickstart (each runnable against `batur serve --mock --media-demo`):

```sh
# Python (stdlib only, 3.8+)
python3 examples/sdk/python/batur_client.py --url http://127.0.0.1:8080 ws --seconds 5 --subscribe mock-1

# Node (>= 22 type-stripping; falls back to SSE if global WebSocket is absent)
node   examples/sdk/node/batur_client.mjs --url http://127.0.0.1:8080 ws --seconds 5 --subscribe mock-1

# TypeScript (Node >= 22 native type-stripping)
node   examples/sdk/typescript/batur_client.ts --url http://127.0.0.1:8080 ws --seconds 5 --subscribe mock-1

# Go (in-process library demo: two sessions against the mock relay)
go     run ./examples/sdk/go
```

## Production notes (current revision)

- Single static binary; sessions persist under a data directory
  (`storage.NewFileStore`).
- Supervisor applies exponential backoff + jitter; stuck-state watchdog
  forces recovery; `session.ready` / `connection.state` events are the
  health signal.
- Graceful shutdown: `batur.Stop(ctx)` stops all sessions cleanly.
- Metrics, Docker image, systemd kit shipped; Postgres adapter queued (see `docs/TASKS.md`).

## Documentation

- `docs/PROJECT_STATE.md` — living state & readiness gate
- `docs/API.md` — HTTP + WebSocket reference (auth, REST, events, ws bridge)
- `docs/BENCH.md` — reproducible `batur bench` numbers & caveats
- `docs/TROUBLESHOOTING.md` — operator field guide for common pitfalls
- `docs/decisions/ADR-0007-storage-adapters-sibling-module.md` — T-204 design
- `docs/architecture/ARCHITECTURE.md` — layering & data paths
- `docs/decisions/` — ADRs (language, deps, concurrency, storage, auth)
- `docs/RESEARCH.md` — protocol research log (no copied code)
- `docs/KNOWN_ISSUES.md` — limitations register
- `docs/TASKS.md` — prioritized backlog

## Disclaimer

Unofficial. WhatsApp is a trademark of Meta Platforms; this project is
an independent protocol implementation for authorized use cases. Use at
your own risk; respect platform terms and applicable law.

## License

MIT — see `LICENSE`.
