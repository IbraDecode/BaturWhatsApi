# ADR-0003 — Session engine owns a single reader goroutine

Date: 2026-09-23
Status: Accepted

## Context

Integration testing exposed a TOCTOU-class bug: the handshake read path
and the steady-state dispatch read path consumed the same socket
concurrently. Frames were stolen nondeterministically between the two
consumers (classic split-brain read).

## Decision

A `session.Session` has exactly **one reader** (`connectionTask`) for the
lifetime of a connection:

1. Dial.
2. Handshake: read ServerHello (handshake code owns the socket).
3. Sync: start `frameConsumer` + keepalive; still the only socket reader.
4. Online: loop `conn.ReceiveBinary` → decrypt → decode → dispatch.

Writers (`Send`, `Request`, pings) run on other goroutines guarded by a
write mutex inside the transport.

## Consequences

- `Start()` returning ONLINE implies the connection is healthy and
  self-owned; supervisors never race with a hidden reader.
- Shutdown is deterministic: cancel ctx → reader sees EOF → `broken` →
  session Done().
- Any future feature (media sockets, sub-connects) must follow the same
  rule (one reader per Conn).
