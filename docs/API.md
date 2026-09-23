# HTTP + WebSocket API

BaturWhatsApi exposes a thin, versioned API over the core engine. The core
library never depends on this surface; REST/SSE/WebSocket live in
`apiserver/` and are one consumer among several.

## Base / auth

- Base path: `/v1`.
- Every endpoint except `/v1/health` and `/metrics` requires
  `Authorization: Bearer $BATUR_API_TOKEN`. If no token is configured the
  server refuses to bind to a non-local interface (fail-closed).
- All payloads are JSON (SSE text/event-stream, WebSocket text frames).

## REST

```
GET  /v1/health                     engine + bus stats (public)
GET  /v1/sessions                   fleet health
GET  /v1/sessions/{id}              one session
DELETE /v1/sessions/{id}            detach
POST /v1/sessions/{id}/iq           raw protocol bridge ({"query": "..."})
POST /v1/sessions/{id}/text         send text ({"to": jid, "text": "..."})
POST /v1/sessions/{id}/sync         resumable contacts/chats sync
GET  /v1/sessions/{id}/contacts     synced contacts snapshot
GET  /v1/sessions/{id}/chats        synced chats snapshot
GET  /v1/sessions/{id}/history      per-chat history (?chat=jid&limit=n)
GET  /v1/events                     Server-Sent Events (all types)
GET  /v1/ws                         WebSocket event bridge (see below)
GET  /metrics                       Prometheus text endpoint (+ ws gauge)
```

### History / media

`GET /v1/sessions/{id}/history?chat=62000001001@s.whatsapp.net&limit=100`
returns bounded per-chat entries:

```json
{
  "chat": "62000001001@s.whatsapp.net",
  "entries": [
    {
      "id": "MOCK123456",
      "chat": "62000001001@s.whatsapp.net",
      "sender": "62000001001@s.whatsapp.net",
      "text": "",
      "type": "image",
      "from_me": false,
      "ack": "received",
      "ts": 1790159399,
      "media": {
        "Kind": "image",
        "URL": "https://mock.local/media/batur-demo.jpg",
        "MIME": "image/jpeg",
        "Caption": "Batur demo snapshot",
        "Width": "640",
        "Height": "480"
      }
    }
  ]
}
```

History is a bounded ring (256/chat) with ack tracking
(pending/sent/delivered/read/received/failed).

## Server-Sent Events

`GET /v1/events` streams one JSON object per event:

```
data: {"seq":9,"type":"message.sent","session":"mock-1","time":"...","data":{...}}
```

`data` is the public domain payload of that event type; for inbound engine
nodes it is the raw protocol node as-is (see KNOWN_ISSUES — inbound media
carries `media` when converted through `api.OnMessage`).

## WebSocket event bridge (`/v1/ws`)

Upgrade path (RFC 6455, text frames). After a successful handshake the
server sends a `hello`, then expects client command frames.

### Server -> client frames

```json
{"type":"hello","data":{"engine":"baturwhatsapi","version":"0.1.0"}}
{"type":"result","op":"send","ok":true,"id":"MESSAGE-ID"}
{"type":"result","op":"sync","ok":true}
{"type":"result","op":"subscribe","ok":true,"session":"mock-1"}
{"type":"error","error":"bad command frame"}
{"type":"pong"}
{"type":"<event>","seq":9,"session":"mock-1","time":"...","data":{...}}
```

Events reuse the same envelope as SSE. A 25 s silent server-ping keeps
intermediaries and the peer alive (send `ping` to get `pong` at your end).

### Client -> server commands

| op | fields | effect |
|----|--------|--------|
| `ping` | — | liveness ping; server replies `pong` |
| `send` | `session`, `to`, `text` | enqueue a text send; result carries the message id |
| `sync` | `session` | trigger contacts/chats sync; result when done |
| `subscribe` | `session`, `jid` | only forward that session's events; `jid` narrows to messages to/from one chat (`""` = all chats) |

Streaming example (Python):

```python
# zero-dependency WS client shipped in examples/sdk/python/batur_ws.py
from batur_ws import stream
stream("ws://127.0.0.1:8080/v1/ws", token="devtoken", seconds=5)
```

Working SDK examples (zero dependency) live in `examples/sdk/`:

```
python3 batur_client.py --url http://127.0.0.1:8080 --token "" sessions
python3 batur_client.py --url http://127.0.0.1:8080 --token "" ws --subscribe mock-1
node   batur_client.mjs ws --subscribe mock-1        # needs Node >= 22
node   batur_client.ts  ws --subscribe mock-1        # Node type-stripping
```

## Error handling

Errors return `{"error": "..."}` with a 4xx/5xx status. WS command errors
come as `{"type":"result","op":"<op>","ok":false,"error":"..."}`.