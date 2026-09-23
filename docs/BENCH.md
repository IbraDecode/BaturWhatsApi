# Performance baseline

Reproducible micro-benchmarks shipped as `batur bench`. They cover the
hot paths the engine spends its CPU on: binary node codec and X25519
keygen (one full handshake per keypair).

## What is measured

```
node encode: 200000 ops ...   MarshalDict on a "message" node carrying
                              id/from/type/t attrs and a <plain> child
node decode: 200000 ops ...   Decode on the marshaled bytes (with dict
                              tokenization)
x25519 keygen: 5000 ops ...   noise.NewKeyPair (one X25519 keypair per
                              handshake, also used for cert chains)
```

Numbers below come from `batur bench` (Go 1.27.1, 2-core / 2 GB
container). Run any time locally:

```sh
make bench         # or: go run ./cmd/batur bench
```

## Numbers (typical, 2-core 2 GB)

| operation      | ops / s |
|----------------|---------|
| node encode    | ~500 k  |
| node decode    | ~550 k  |
| x25519 keygen  | ~17 k   |

A 200k-node encode pass (~0.4 s) decodes in the same ballpark.
Keygen is dominated by X25519 scalar arithmetic; the engine only
generates a new keypair on handshake or cert rotation, so 17 k/s is
far above any session rate a single core will see in production.

## Caveats

- Micro-benchmarks are not representative of full session throughput
  (which is dominated by network and by e2e Double-Ratchet work).
- Numbers vary with CPU and Go version. The matrix above is
  intentionally narrow to stay comparable across runs; expand when
  a real end-to-end throughput test exists.
