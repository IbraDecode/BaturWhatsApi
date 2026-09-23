# ADR-0001 — Language: Go

Date: 2026-09-23
Status: Accepted

## Context

BaturWhatsApi is a persistent, multi-session, low-memory, always-on
communication engine that terminates long-lived WebSocket connections with
binary framing, heavy crypto and per-session concurrency. Candidates:
Go, Rust, TypeScript/Node.js.

## Evaluation

| Factor        | Go                      | Rust                    | Node/TS                   |
|---------------|-------------------------|-------------------------|---------------------------|
| Idle memory   | low (MB-scale)          | lowest                  | high (V8)                 |
| Concurrency   | goroutines, per-session | tokio (more ceremony)   | event loop, CPU-bound pain|
| Stdlib crypto | X25519/AES-GCM/HKDF/HMAC✅ | excellent             | via node:crypto           |
| Binary codec  | fast, slices, unsafe ok | fastest                 | Buffer (GC churn)         |
| Deploy        | single static binary ✅ | compile-heavy           | needs runtime             |
| Cross-compile | trivial ✅              | harder                  | n/a                       |
| Ecosystem fit | excellent (whatsmeow, GOWA, wa-go prove fit) | good | largest |
| Iteration     | fast build, race detector | slower builds         | fast dev, slow at scale   |

Rust is competitive on raw performance; Go wins on build/deploy
ergonomics, the standard-library crypto surface we need (zero external
crates in the core), and the team's iteration speed for 24/7 autonomous
development. Node fails the low-memory/CPU targets for N concurrent
sessions.

## Decision

Core engine, protocol, security, session, storage and CLI are written in
**Go** (module `github.com/ibradecode/baturwhatsapi`, built with Go ≥ 1.23).

Multi-language SDKs (Python/Node/etc.) will be built later as thin
clients over the REST/WebSocket API surface (ADR-0006, planned) — they do
not replace the Go core.

## Consequences

- Single static binary deployment; trivial container images (scratch).
- CGO stays OFF; no system dependency beyond TLS (stdlib crypto).
- GC tuning is a known future task for per-session buffers (documented
  in performance backlog).
