# RESEARCH LOG

Sources consulted (protocol facts only — no code copied):

## Primary protocol facts (2026-09-23, via whatsmeow main branch, public)

- Token dictionaries v3: single-byte tokens 236, double-byte 4×256,
  DictVersion=3 (`binary/token/token.go`).
- Tag constants: ListEmpty 0, Dictionary0-3 = 236-239, InteropJID 245,
  FBJID 246, ADJID 247, List8 248, List16 249, JIDPair 250, Hex8 251,
  Binary8 252, Binary20 253, Binary32 254, Nibble8 255; PackedMax 127.
- Nibble/Hex pack rules, 20-bit binary length (`& 0x0F` high nibble),
  ADJID = tag + agent + device + user; JIDPair = user@server.
- Wire payload flag byte: `2&dataType` → zlib stream (leading 0x00 = raw).
- Node layout: listSize(1+2*attrs+content), attrs (even pairs), content.
- Noise start pattern (32 bytes): `Noise_XX_25519_AESGCM_SHA256` + 4 zero
  bytes; h=pattern, k=SHA256-h AES-GCM; MixKey = HKDF-SHA256(ikm, ck) →
  (write, read) halves, key=read, salt←write; finish derives
  transport (write,read) with empty ikm, swapped per direction.
- Transport ciphers: AES-256-GCM, nonce = 12 bytes, counter in bytes
  [8:12] big-endian; handshake messages via protobuf `HandshakeMessage{
  ClientHello{ephemeral=1,payload=3}, ServerHello{ephemeral=1,static=2,
  payload=3}, ClientFinish{static=1,payload=2}}`.
- Server identity: CertChain (intermediate+leaf Ed25519 signatures,
  64-byte sigs, serial/validity fields, leaf key == server static).

## Security primitives (standard-track)

- RFC 5869 (HKDF) — official SHA-256 test vectors used verbatim.
- RFC 5114/Noise protocol framework (XX pattern + fallback semantics).
- RFC 6455 (WebSocket): frame opcodes, masking, handshake accept key,
  fragmentation rules; stdlib `net/http` deliberately NOT used for
  handshake response parsing (double-buffering bug; see ADR-0003 notes).

## Reference implementations surveyed for failure/architecture patterns

- Baileys (TypeScript) — connection state & dictionary usage notes.
- whatsmeow (Go) — socket structure, handshake timeout defaults
  (20s noise response), auto-reconnect loop shapes.
- GOWA / wa-go — kept in mind for multi-device behaviors (not consulted
  line-by-line yet).

## Decision trail

- Own implementation of every layer (charter). Facts above are protocol
  data (publicly documented in these projects / reverse-engineering
  writeups); no source code was copied. License contamination avoided:
  the repo contains no code derived from MPL/GPL projects.

## Open research questions (feed into TASKS)

1. Exact WhatsApp web *modern* framing of handshake frames (length-
   prefixed vs raw per WS message) against a live server capture.
2. Sub-connect / media connection semantics (separate noise per stream?).
3. Sync checkpoints (`cursor`, `snapshot` payload formats) for Phase 2.
4. Pairing-code + companion registration flow for multi-device.
