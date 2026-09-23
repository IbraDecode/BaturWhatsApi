# KNOWN ISSUES & LIMITATIONS

Honest register. Anything production-relevant lives here until fixed.

## Critical (P0/P1)

1. **No Signal e2e crypto yet.** `api.SendText` returns
   `ErrNotImplemented`. The engine can connect, authenticate, exchange
   protocol nodes and stream events, but cannot yet encrypt/decrypt
   WhatsApp messages end-to-end. Until T-101/T-102 land, this is NOT a
   messaging product. Status: open.
2. **Server authentication = first-contact pin, not WA cert chain.**
   `session.ServerAuth` policy is pluggable and fail-closed
   (`nil` = reject), but the real Ed25519 CertChain verifier is not
   implemented (T-001). Trust-on-first-use carries a MITM window on the
   first connection.
3. **Race suite not yet green.** All tests pass without `-race`; the
   race run needs CI time + any fixes surfaced (T-003).

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

- 2026-09-23: Handshake double-finish removed; session now reads once
  via single-reader design (ADR-0003, fixes nondeterministic frame loss).
- 2026-09-23: `ws.readFrame` payload-drop bug + mask-bit placement fixed
  (byte-level wire tests green).
- 2026-09-23: Pipe transport EOF propagation after remote close fixed.
- 2026-09-23: `statemachine.Move` self-deadlock (nested unlock) fixed.
