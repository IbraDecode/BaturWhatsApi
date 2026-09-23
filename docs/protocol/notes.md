# Protocol notes

## Token dictionary (WAWebMulti)

- JSON schema: `{"version":N,"single":[...],"double":[[...],[...],[...],[...]]}`
  embedded at build time (`protocol/token/tokens_v3.json`, v3 = the
  currently-known WhatsApp web revision, 236 single + 4×256 double).
- Swapping dictionaries: construct `token.Dictionary` from JSON and pass
  it into `session.Options.Dict` — encoders/decoders carry no global
  state.

## Node encoding summary (batur's own implementation)

```
node := listSize(1 + 2*attrs + hasContent) tag attrK attrV … content
content := nil | string | bytes | JID | node-list
string flavor priority: single-token byte → double-token (236+dict, idx)
  → nibble-packed [0-9-.] → hex-packed [0-9A-F] → binary(8/20/32) raw
JID: ADJID(user-device, servers s.whatsapp.net/lid/hosted*/…) |
     JIDPair | FBJID(msgr) | InteropJID
stream flag byte: 0x00 raw | 0x02/0x03 zlib
```

Notes:
- Empty-string attributes are omitted at encode (wire rule; matches
  reference behavior).
- `Tag == "0"` serializes as List8+ListEmpty (legacy null-node quirk).
- Attribute order is sorted for byte-deterministic streams (engine-side
  only; servers accept any order).
- Packed values with odd length set 0x80 on the length byte and pad
  nibble 0xF in the final pair (decoder trims).
