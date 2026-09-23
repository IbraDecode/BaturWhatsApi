# TASKS — prioritized queue

Legend: P0 blocker · P1 core · P2 feature/reliability · P3 polish.
Status: TODO / IN_PROGRESS / BLOCKED / DONE.

## P0 — engine correctness & safety (next actions)

| # | Task | Status | Notes |
|---|------|--------|-------|
| T-001 | Wire cert-chain server verification (Ed25519 + CertChain proto over pb) | DONE | security/wacert + session.TrustedRootAuth; mock serves real chains |
| T-002 | Session-scale memory/CPU benchmark harness (idle + message load) | DONE | internal/bench: footprint regression guard (512KiB budget), throughput 52K rps, codec/handshake benches |
| T-003 | `-race` clean run of full suite (currently passes w/o race) | DONE | 3 race classes fixed (cipher mutex, session write ordering lock, supervisor sess pointer) |
| T-004 | Storage hardening: dir fsync on write, manifest crash-test | TODO | ADR-0004 consequences |
| T-005 | Secrets-at-rest sealing (AES-256-GCM SecureKV + keygen + serve flags) | DONE | closes audit risk #2 (2026-09-23) |

## P1 — protocol completeness

| # | Task | Status |
|---|------|--------|
| T-101 | Signal e2e crypto engine: identity keys, prekeys, X3DH/Double Ratchet (own implementation; stdlib crypto) | DONE | security/e2e: verified bundles, out-of-order skipping, replay/tamper guards, persisted ratchets |
| T-102 | WhatsApp wire-compatible SignalMessage + live receipts | BLOCKED | needs live WhatsApp account/network to verify byte-for-byte Signal interop (human action + real device). Engine-to-engine e2e already live via mock relay. |
| T-103 | Registration & QR/pairing-code flow (companion platform) | TODO |
| T-104 | Sync engine: contacts, chats, history, appstate + checkpoints | IN_PROGRESS | contacts+chats+message-history DONE; appstate/history-replay via server pending |
| T-105 | Receipt/ack state model in domain events | DONE | AckState pending/sent/delivered/read/received/failed; monotonic rank in HistoryStore |
| T-106 | Keep-alive policy tuning: exponential idle ping, server config-driven | TODO |

## P2 — features & platform

| # | Task | Status |
|---|------|--------|
| T-201 | Media engine: download/upload pipeline (encrypt/decrypt, refs) | IN_PROGRESS | Attachment envelope parsing (api.Media: image/video/audio/document/location/contact/sticker/app via legacy-XML child tags) + history `media` field + mock image demo, all -race green; upload/download + protobuf descriptor mapping pending (needs live capture) |
| T-202 | REST + WebSocket API servers over core (core stays REST-free) | IN_PROGRESS | v1 REST+SSE+WS bridge live (apiserver/); device pairing/registration endpoints pending |
| T-203 | SDKs: Python + TypeScript thin clients over API | DONE | Python (REST+SSE+WS RFC6455 stdlib), Node (fetch+global WebSocket), TypeScript (types, runs on Node22 type-stripping); ALL subcommands verified live vs serve --mock (health/sessions/get/text/events-SSE/ws) |
| T-204 | Postgres/SQLite storage adapters (multi-node) | TODO |
| T-205 | Metrics endpoint (Prometheus) + structured health | DONE | /metrics text/0.0.4 (T-205, 2026-09-23) |
| T-206 | Group/newsletter domain models + operations | TODO |
| T-207 | Dockerfile + systemd/24/7 deployment kit | IN_PROGRESS | Dockerfile (scratch+CGO=0) + docs/deploy (unit, keygen, TLS note); image build not locally testable (no docker) |
| T-208 | Protocol fuzz corpus + regression fixtures from real captures | IN_PROGRESS | Go fuzz targets for codec decoder/encoder + pb wire (native -fuzz); crash fixture committed; real-capture regressions pending (needs live device) |

## P3 — polish

| # | Task | Status |
|---|------|--------|
| T-301 | Golden-file tests for every handshake message shape | TODO |
| T-302 | CLI: config file (YAML) for production runs | TODO |
| T-303 | Tracing spans across dial/handshake/sync boundaries | TODO |
| T-304 | Release automation (versioned binaries, changelog) | TODO |

## Recently completed (keep 5)

- ✅ Full in-process end-to-end demo (`batur demo`) with event stream
- ✅ Supervisor with backoff+jitter recovery, chaos test passing (T from P0 → done)
- ✅ Multi-session isolation verified (unique keys, 3 sessions)
- ✅ Session resume-across-restart (file KV)
- ✅ Single-reader concurrency contract (ADR-0003) + fail-closed auth tests
