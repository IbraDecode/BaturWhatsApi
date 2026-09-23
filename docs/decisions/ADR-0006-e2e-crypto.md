# ADR-0006 — e2e crypto: X3DH + Double Ratchet, stdlib-only, own envelope

Date: 2026-09-23
Status: Accepted

## Context

Messaging requires per-peer forward-secret, post-comprom secure session
crypto. Options: vendor libsignal-style code, build our own, or delay.

## Decision

Implement the standard algorithms ourselves inside `security/e2e` using
only Go stdlib primitives (X25519 via crypto/ecdh, Ed25519, AES-256
CBC/GCM, SHA-256/HMAC, HKDF from our own RFC-verified package):

- X3DH (DH1..DH4 with documented OPK-absent marker) — identity keys and
  signed prekeys authenticated by Ed25519 self-certificates.
- Double Ratchet with symmetric one-KDF-per-event root advancement:
  receiving a new remote key performs exactly one root step; the next
  Encrypt performs the paired sending step. Out-of-order keys are
  buffered in a bounded skip map (1000).
- Per-message body keys: HKDF-expand(msgKey) → AES-256-GCM key+IV;
  AAD binds ratchet pub + header.
- Envelope serialization is the engine's own (`protocol/pb`), NOT a copy
  of WhatsApp's SignalMessage proto. T-102 maps to their wire.

## Consequences

- Full audit surface in-repo; RFC/standard algorithms, no exotic curves.
- Not yet wire-identical to WhatsApp (explicit, staged).
- Persistence format (`MarshalState`) embeds private chain state: treat
  the storage directory as secret material (see security/notes).
- Future: post-quantum prekey encapsulation is a research item, not a
  v1 requirement.
