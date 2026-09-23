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
| T-102 | `api.SendText` / media-free message send over real flow | IN_PROGRESS | engine-to-engine flow live (api.SendText + mock relay); WhatsApp wire mapping + receipts pending |
| T-103 | Registration & QR/pairing-code flow (companion platform) | TODO |
| T-104 | Sync engine: contacts, chats, history, appstate + checkpoints | IN_PROGRESS | framework live (sync/, resumable, protocol-tested); WA payload decoders pending |
| T-105 | Receipt/ack state model in domain events | TODO |
| T-106 | Keep-alive policy tuning: exponential idle ping, server config-driven | TODO |

## P2 — features & platform

| # | Task | Status |
|---|------|--------|
| T-201 | Media engine: download/upload pipeline (encrypt/decrypt, refs) | TODO |
| T-202 | REST + WebSocket API servers over core (core stays REST-free) | IN_PROGRESS | v1 REST+SSE live (apiserver/); WS bridge + pairing endpoints TODO |
| T-203 | SDKs: Python + TypeScript thin clients over API | TODO |
| T-204 | Postgres/SQLite storage adapters (multi-node) | TODO |
| T-205 | Metrics endpoint (Prometheus) + structured health | TODO |
| T-206 | Group/newsletter domain models + operations | TODO |
| T-207 | Dockerfile + systemd/24/7 deployment kit | TODO |
| T-208 | Protocol fuzz corpus + regression fixtures from real captures | TODO |

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
