# Security notes (v0.1)

## Handshake

`Noise_XX_25519_AESGCM_SHA256` in WhatsApp's web variant, implemented in
`security/noise`:

- Pattern = 32 bytes: `"Noise_XX_25519_AESGCM_SHA256" + 0x00×4` is both
  the initial hash h and the initial chain key.
- The transport's `BindingHeader()` (first request line + response
  status) is authenticated into h (channel binding — a proxy that
  re-writes either cannot be silent).
- `MixKey` = HKDF-SHA256(ikm, salt=ck) → (ck, k): ck becomes salt,
  cipher key = k. Counter resets per MixKey (handshake message ciphers).
- `ClientFinish` split into `ReadServerHello` → (ServerAuth gate) →
  `WriteClientFinish`, so session code can refuse to send identity
  before the server is verified (ADR-0005, fail-closed).

## Transport ciphers

AES-256-GCM per direction; IV = 12 zero bytes with the 32-bit big-endian
message counter in bytes 8..11. Final keys derive from the post-handshake
chain (extract+expand with empty ikm; initiator send = first half).

## Key material

- X25519 noise static key (persistent), X25519 identity key (reserved
  for Signal engine, Phase 2).
- Secrets live in `storage.KV` (`session/<id>/credentials` JSON). File
  store uses 0600 and directory 0700.
- Crypto is stdlib only (`crypto/ecdh`, `crypto/aes`, `crypto/cipher`,
  `crypto/hmac`, `crypto/sha256`, `crypto/rand`). Hand-rolled parts are
  HKDF (RFC-verified) and the Noise state machine itself.

## Open items

- CertChain verification (T-001), constant-time checks for pinned-key
  comparison (currently `bytes.Equal` — non-secret comparison but worth
  tightening in audit), prekey rotation policy for Signal phase.
