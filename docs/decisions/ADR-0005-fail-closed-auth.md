# ADR-0005 — Fail-closed server authentication policy

Date: 2026-09-23
Status: Accepted

## Context

The noise handshake yields an unauthenticated server static key by
default. WhatsApp web authenticates the server via a pinned Ed25519-secured
CertChain (intermediate → leaf → static key). Until the cert-chain
verifier is ported/implemented, a session that simply accepted any static
key would be silently MITM-able.

## Decision

`session.ServerAuth` is a required hook; `nil` aborts the handshake
("ServerAuth policy not configured"). The engine ships:

- `pinFirstContact`: trust the key observed on first registration and pin
  its hash into storage (`server_static`); refuse on mismatch. Suitable
  for tests/mock and initial rollout.
- `trustedKeys`: explicit allowlist.

## Consequences

- No session can reach ONLINE without an explicit trust decision —
  auditable and testable.
- First-contact pinning has a window on genuine first use; the WA cert
  verifier (backlog P1) removes it entirely.
- Wire-level cert-chain verification (Ed25519 over stdlib `crypto/ed25519`)
  is feasible without dependencies; it is scoped, not vague.
