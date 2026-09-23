# Examples

## SDK bridges (talk to a running `batur serve`)

The Go core is multi-language-ready through the HTTP/SSE API:

| Language | File | Requirements |
|----------|------|--------------|
| Python   | `sdk/python/batur_client.py` | Python 3.8+ stdlib only |
| Node.js  | `sdk/node/batur_client.mjs`  | Node 18+ (global fetch), zero deps |
| Go       | `sdk/go/main.go`             | this module |

Start the engine, then:

```bash
batur serve --mock --data ./data --bind 127.0.0.1:8080
python3 examples/sdk/python/batur_client.py --url http://127.0.0.1:8080 sessions
node examples/sdk/node/batur_client.mjs --url http://127.0.0.1:8080 events 10
```

When `BATUR_API_TOKEN` is set, pass `--token`.

## Embedding

Library use (`api` package) is shown in `sdk/go/main.go` — it attaches
two in-process sessions against the mock relay and exchanges encrypted
messages end-to-end.
