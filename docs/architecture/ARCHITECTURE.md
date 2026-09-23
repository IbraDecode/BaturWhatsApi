# Architecture — BaturWhatsApi v0.1

## Layering

```
┌─────────────────────────────────────────────────┐
│  cmd/batur (CLI)                                │
├─────────────────────────────────────────────────┤
│  api  (public façade, domain models, events)    │
├──────────────────────┬──────────────────────────┤
│  supervisor          │  events (bus)            │
│  (24/7 fleet,        │  (ordering, backpressure,│
│   backoff+jitter,    │   panic isolation)       │
│   watchdogs)         │                          │
├──────────────────────┴──────────────────────────┤
│  session (one device connection lifecycle)      │
│  statemachine (explicit 10-state FSM)           │
├─────────────────────────────────────────────────┤
│  internal/wapb (handshake messages)             │
│  protocol/binary (WAWebMulti codec) ─┐          │
│  protocol/pb (protobuf wire)         ├─ protocol │
│  protocol/token (dictionaries)      ─┘          │
│  security/noise (XX/AES-GCM chain)  ┐           │
│  security/hkdf (RFC 5869)           ┘ security  │
├─────────────────────────────────────────────────┤
│  transport (Conn contract, pipe, ws client)     │
│  storage (KV abstraction, memory/file)          │
└─────────────────────────────────────────────────┘
```

## Data path (received)

```
WS/TCP bytes → transport.Conn.ReceiveBinary → session.connectionTask
  → noise transport cipher (AES-256-GCM, ctr IV)
  → binary node decode (WAWebMulti + token dictionaries + zlib flag)
  → dispatch: iq|result correlation → requests map
              message/receipt/presence/ib → domain events on the bus
  → api.OnMessage / OnConnectionState subscribers (public models only)
```

## Data path (sent)

```
api / session.Request / keepalive pings
  → binary encode (deterministic attr order for golden tests)
  → MarshalDict + flag byte
  → noise cipher Seal (counter IV)
  → transport.Conn.SendBinary (WS masking for clients)
```

## Connection lifecycle (state machine)

STOPPED → STARTING → CONNECTING → AUTHENTICATING → SYNCING → ONLINE.
Failure edges: ONLINE → DEGRADED (inbound silence) → ERROR; supervisor
reports RECONNECTING while a session waits in its backoff window
(`Health().State`), then a fresh session object re-enters STARTING.
RECONNECTING is therefore the fleet-level view of the retry loop while
per-session machines stay strictly per-connection.

## Isolation model

- One `Session` == one dialer, one conn, one cipher pair, one FSM, one
  storage key-prefix (`session/<id>/…`), one event stream.
- `Supervisor` owns N sessions; sessions never share mutable state.
- Multi-language / multi-transport future: dialers are pluggable at the
  session boundary (sub-connects for media are planned there).

## Public API stability

`api.*` types (Message, Target, SessionStatus, subscription helpers) are
the only exported surface applications should use. Protocol nodes stay
internal (`protocol/binary.Node` is not re-exported through api
signatures in user-facing handlers).

## Persistence

Credentials (noise/identity X25519 seeds, registration id, pinned server
static key, account JID) serialize to JSON under the session KV prefix.
Process restart → new `Session` with same id/store resumes (verified by
integration tests).

## Security posture

See ADR-0005. No crypto is hand-rolled beyond HKDF (RFC-verified).
Transport ciphers are AES-256-GCM with 96-bit counter IVs per direction.
