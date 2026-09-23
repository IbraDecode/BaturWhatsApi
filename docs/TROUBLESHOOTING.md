# Troubleshooting

A small field guide for the most common operator/developer issues. Most
of these come from running BaturWhatsApi against the mock relay; live
WhatsApp adds additional surfaces that are explicitly called out.

## Authentication

**`/v1/ws` upgrade rejected with 401**
The HTTP bridge requires `Authorization: Bearer $BATUR_API_TOKEN`.
When `serve` is started without a token it refuses to bind to anything
other than localhost (`BATUR_API_TOKEN` empty + non-localhost bind is
fail-closed). Check both: `BATUR_API_TOKEN` is set, and the WS
handshake passes it as a Bearer header.

**REST returns `{"error":"bad token"}`**
Same root cause: the daemon's token differs from the caller's. Pass
`-H "Authorization: Bearer $BATUR_API_TOKEN"` and make sure both sides
have the same string.

## Connection state

**Session stuck in `Reconnecting` / `Error`**
The supervisor retries with exponential backoff. Look at
`/v1/sessions/{id}` for `Retries` and `LastOnline`. The engine only
reaches `Online` after a full Noise_XX handshake and cert chain check,
so the most common culprits are:

- **Trust root mismatch.** Real deployments must pass
  `session.TrustedRootAuth(wacert.RootPubKey)` to `Attach`. The mock
  ships its own root and accepts only that.
- **Stale device record.** `DELETE /v1/sessions/{id}` and re-Attach.
- **Outdated token dictionary.** `--dict`/`Dict` should be
  `protocol/token.Default()` unless you deliberately pin a different
  one.

## Sending

**`POST /v1/sessions/{id}/text` returns `{"ok":false,"error":"..."}`**
The session must be `ONLINE`. Check `/v1/sessions/{id}` first.

**`send` over WS returns `{"ok":true,"id":"..."}` but no message arrives**
The engine enqueues the e2e encrypted envelope locally and returns
success once the send path completes. Delivery to the recipient is the
counterparty's relay's problem; from the sender's vantage point the
message is gone. Use `GET /v1/sessions/{id}/history?chat=<jid>` to see
if it landed in the local ring.

## History

**`/history` is empty even after `text` returned `ok:true`**
Two reasons:

1. `Options.History` was left at its default (`false`). Either set it
   to `true` at `api.New` or run `batur serve --history` (default `true`).
2. The bus subscriber runs on its own goroutine; the entry appears
   after a short async settle. Poll with a brief deadline (a few
   hundred milliseconds).

**`/history` pagination with `cursor`**
The chat ring is bounded (256 entries); `next_cursor=-1` means there
is nothing further.

## Media

**An inbound `image`/`video`/`document` shows up in the bus but the
`media` field is `null`**
The engine only extracts media from the **legacy-XML child-tag**
scheme (`<image url="..." mime="..." caption="..."/>` inside a
`message` node). Production WhatsApp uses protobuf descriptors and
real-device media decoding is still pending (T-201). Use
`batur serve --mock --media-demo` to exercise the parser locally.

## Storage

**`/history` or other persisted reads return what looks like fresh data
on every restart**
The `--data` directory is the only persistent state. Without it,
`serve` runs in-memory and every restart starts over. Confirm with
`ls $BATUR_DATA_DIR` after a restart.

**Store returns `ErrWrongKey` on startup**
You changed `BATUR_MASTER_KEY` / `--seal-key` between runs. The store
seals every value with that key and refuses to open when it cannot
unwrap the manifest header. The keyfile path (`--seal-key-file`) must
contain 64 hex characters (32 bytes).

## CLI

**`batur version` shows `(development)`**
That's `Channel` (a separate concept). What you want is the `Version`
stamp injected via `-ldflags -X .../internal/version.Version=$TAG` at
release time. Locally it will read whatever default is in
`internal/version.go`.

**`batur bench` numbers vary run to run**
Micro-benchmarks are CPU and OS-schedule sensitive. The values in
`docs/BENCH.md` are typical for a 2-core 2 GB container; treat
deviations smaller than 20 % as noise.

## CI / fuzz

**`fuzz: elapsed: ..., new interesting: N`**
That is normal — the seed corpus grows whenever the fuzzer finds an
input that exercises a previously-uncovered branch. New interesting
entries are stored under `testdata/fuzz/<FuzzName>/`; review and commit
if they cover a real shape.

**`fuzz` panics with a saved crash**
The crash body is written next to the corpus; promote it to a fixture
test, fix the underlying issue, then commit the fixture so the
regression stays caught. The 2026-09-23 decoder crash in
`testdata/fuzz/FuzzDecodeDefault/` is a worked example.
