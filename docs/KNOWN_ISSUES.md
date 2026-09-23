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
5. **WebSocket server mode serves `/v1/ws` behind bearer auth** (RFC6455
   handshake + unmasked server frames). The raw `ServeWS` loopback helper
   remains test-only; production deployments should terminate TLS/WSS at
   a reverse proxy (see docs/deploy/DEPLOY.md).
6. **Media metadata (T-201) parses the legacy-XML child-tag scheme
   (image/video/audio/document/...) and is verified only against the mock
   server.** Live-device WhatsApp messages carry protobuf descriptors
   (WebMessageInfo etc.); mapping those is pending a real capture and may
   differ. Upload/download pipelines are not implemented yet.
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

- 2026-09-23: **secrets-at-rest** now sealed with AES-256-GCM via
  `storage.SecureKV` (`batur serve --seal-key[-file]` /
  `BATUR_MASTER_KEY`, `batur keygen`); key-path bound as AEAD AAD
  (replay-to-other-key rejected), wrong master refuses to boot (fail
  closed), verified on disk: no plaintext seeds, sealed resume works.

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

## Bounded-scope notes
- API-server WS bridge is plain ws:// (no permessage-deflate); terminate WSS upstream and forward /v1/ws. The ws package also enforces unmasked server frames / masked client frames per RFC 6455.
- Server-mode ws.Un upgrade path is used only by apiserver; engine transport keeps using the heavy-ws client for WhatsApp-style traffic.

## Security/robustness fixes
- [T-208] Fuzzing found & fixed a decoder crash: packed-string with odd-length flag and zero content could panic with a negative slice (`decoder.go`). Regression fixture committed under protocol/binary/testdata/fuzz/. 218K+ decode execs now clean.
