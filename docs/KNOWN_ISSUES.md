# KNOWN ISSUES & LIMITATIONS

Honest register. Anything production-relevant lives here until fixed.

## Critical (P0/P1)

1. **e2e engine (X3DH + Double Ratchet) implemented and wired into
   `api.SendText`, but not yet against a LIVE WhatsApp relay.** Current
   end-to-end proof: two engine sessions through the mock relay (server
   acts as recipient endpoint). WhatsApp's SignalMessage/Cert wrapping is
   T-102; the mock-relay semantic (server decrypts) is demo-only and
   MUST NOT be used for production routing. Status: partially resolved.
2. **Cert-chain verification implemented; trust root pinning list not
   yet wired into the default production dial path.** Use
   `session.TrustedRootAuth(wacert.RootPubKey)` for real deployments
   (verified against synthetic + tampered chains in tests).

## Moderate

4. **File store crash-consistency is per-file atomic, not fsync'd to
   disk.** Power loss may lose the newest write; no torn-state corruption
   expected. (T-004.)
5. **WebSocket client is client-role only** (WhatsApp edge). The bundled
   `transport/ws` test-server exists solely for loopback tests/demo —
   do not expose it as a service.
6. **Idle-memory claims are unmeasured.** "Low-memory" is a design goal
   (no V8/CGO, slice pools planned), not a benchmarked fact (T-002).
7. **Dictionary revision is v3 (DictVersion=3)** extracted from
   whatsmeow as protocol data. If WhatsApp bumps the dictionary table,
   token JSONs must be regenerated; the Dictionary type supports this
   (JSON-embeddable, hot-swap by version).

## Minor / design notes

8. `statemachine.Force` bypasses validation by design (recovery hatch);
   history marks forced transitions with `!` prefix.
9. Events bus `PolicyDropOldest` drops per-subscriber, never globally;
   stats count drops.
10. `binary.Node.Attrs` map iteration is sorted at encode time for
    golden-test determinism only; servers must not rely on ordering.
11. The mock server's "account JID" and cert blob are synthetic —
    useful for integration, never for wire compatibility claims.

## Resolved (keep for archaeology)

- 2026-09-23: T-001 CertChain verifier (security/wacert, Ed25519 stdlib)
  + TrustedRootAuth/PinFirstContact policies; race suite green (T-003):
  noise.Cipher mutex, session writeMu (seal+send ordering), supervisor
  m.sess locking, mock server write locks.

- 2026-09-23: Handshake double-finish removed; session now reads once
  via single-reader design (ADR-0003, fixes nondeterministic frame loss).
- 2026-09-23: `ws.readFrame` payload-drop bug + mask-bit placement fixed
  (byte-level wire tests green).
- 2026-09-23: Pipe transport EOF propagation after remote close fixed.
- 2026-09-23: `statemachine.Move` self-deadlock (nested unlock) fixed.
