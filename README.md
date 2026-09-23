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

Core runtime is alive end-to-end: dial → noise handshake → binary
protocol → encrypted node exchange → events → multi-session supervision
with automatic reconnect, sessions survive restarts. See
`docs/PROJECT_STATE.md` for the honest readiness matrix — Signal e2e
messaging is the next milestone.

## Quickstart

Requires Go ≥ 1.23.

```bash
make test        # full suite
make race        # race detector (slow CPU container: may take minutes)
make bench       # codec / crypto micro-benchmarks

# run the whole engine in one process (mock WhatsApp-web server):
go run ./cmd/batur demo
go run ./cmd/batur doctor
go run ./cmd/batur serve --mock --bind 127.0.0.1:8080   # REST + SSE API
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
POST /v1/sessions/{id}/text         501 until the Signal engine (T-101)
GET  /v1/events                     Server-Sent Events (all types)
Authorization: Bearer $BATUR_API_TOKEN   (required for non-local bind)
```

## Production notes (current revision)

- Single static binary; sessions persist under a data directory
  (`storage.NewFileStore`).
- Supervisor applies exponential backoff + jitter; stuck-state watchdog
  forces recovery; `session.ready` / `connection.state` events are the
  health signal.
- Graceful shutdown: `batur.Stop(ctx)` stops all sessions cleanly.
- Metrics, Docker image, Postgres adapter: queued (see `docs/TASKS.md`).

## Documentation

- `docs/PROJECT_STATE.md` — living state & readiness gate
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
