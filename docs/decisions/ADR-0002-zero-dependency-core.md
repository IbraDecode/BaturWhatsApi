# ADR-0002 — Zero third-party dependencies in the core

Date: 2026-09-23
Status: Accepted

## Context

Reference implementations (Baileys, whatsmeow, GOWA, wa-go) are research
sources, not dependencies. The project charter demands an independent
engine: own architecture, protocol abstraction, domain model, public API.

## Decision

`go.mod` contains **no third-party requires**. Where a dependency would
normally enter, the engine implements the protocol itself from primary
specs (or stdlib):

- WebSocket: own RFC 6455 client (`transport/ws`), masked frames,
  fragmentation, control frames — stdlib crypto/tls + net only.
- Noise_XK/XX + transport ciphers: own (`security/noise`) over
  `crypto/ecdh` (X25519), `crypto/aes` GCM, `crypto/sha256`, `crypto/hmac`.
- HKDF: own (`security/hkdf`), verified against RFC 5869 vectors.
- Protobuf: minimal wire-codec (`protocol/pb`) — no runtime.
- Token dictionaries: embedded JSON data (`protocol/token`), hot-swappable.

## Consequences

- Supply-chain surface ≈ Go toolchain + stdlib only; trivially auditable.
- More internal code to test; mitigated by golden/RFC vectors + fuzzing.
- WebSocket/server-side code in `transport/ws` is minimal by design
  (tests/demo); production-facing WS termination remains the WhatsApp
  edge's job (client role only).
