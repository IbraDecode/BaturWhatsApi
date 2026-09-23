#!/usr/bin/env python3
"""Minimal RFC 6455 WebSocket client for BaturWhatsApi SDK examples.

Dependency-free (stdlib `socket`, `ssl`, `hashlib`) so the examples stay
runnable on any Python 3.8+ box, mirroring the engine's zero-dependency
rule. Only what the API-server /v1/ws bridge needs: text frames, masked
client writes, unmasked server reads, ping/pong, close, fragmentation.
"""
import base64
import hashlib
import os
import socket
import struct
import time


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 16 << 20


class WSClient:
    def __init__(self, url, headers=None, timeout=30):
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout
        self.sock = None
        self.buf = b""
        self.partial = b""

    # ---- handshake ----
    def connect(self):
        assert self.url.startswith("ws://") or self.url.startswith("wss://"), self.url
        scheme, rest = self.url.split("://", 1)
        hostport, _, path = rest.partition("/")
        path = "/" + path
        host, _, port = hostport.partition(":")
        port = int(port) if port else (443 if scheme == "wss" else 80)
        s = socket.create_connection((host, port), self.timeout)
        s.settimeout(self.timeout)
        if scheme == "wss":
            import ssl
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        self.sock = s
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
            % (path, hostport, key)
        )
        for k, v in self.headers.items():
            req += "%s: %s\r\n" % (k, v)
        req += "\r\n"
        s.sendall(req.encode())
        resp = self._recv_until("\r\n\r\n")
        lines = resp.split("\r\n")
        if "101" not in lines[0]:
            raise RuntimeError("handshake rejected: %r" % lines[0])
        accept = None
        for line in lines[1:]:
            if line.lower().startswith("sec-websocket-accept:"):
                accept = line.split(":", 1)[1].strip()
        expected = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()
        ).decode()
        if accept != expected:
            raise RuntimeError("bad websocket accept")

    def _recv_until(self, marker_text):
        marker = marker_text.encode()
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed during handshake")
            self.buf += chunk
        data, self.buf = self.buf.split(marker, 1)
        return (data + marker).decode("utf-8", "replace")

    # ---- framing ----
    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def send_text(self, text):
        payload = text.encode()
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        header = [0x81]
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n <= 0xFFFF:
            header.extend((0x80 | 126, (n >> 8) & 0xFF, n & 0xFF))
        else:
            header.extend((0x80 | 127,))
            header.extend(struct.pack("!Q", n))
        self.sock.sendall(bytes(header) + mask + masked)

    def recv_message(self):
        """Returns (opcode, text) for the next data frame (text frames only)."""
        while True:
            opcode, payload = self._recv_frame()
            if opcode == 0x8:  # close
                raise EOFError("websocket closed by server")
            if opcode == 0x9:  # ping -> pong
                self.send_pong(payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode in (0x0, 0x1, 0x2):
                if opcode == 0x0:  # continuation
                    self.partial += payload
                    data, self.partial = self.partial, b""
                else:
                    data = payload
                return opcode, data.decode("utf-8", "replace")

    def send_pong(self, payload):
        self.sock.sendall(bytes((0x8A, 0x80)) + os.urandom(4) + payload)

    def _recv_frame(self):
        hdr = self._read_exact(2)
        opcode = hdr[0] & 0x0F
        n = hdr[1] & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._read_exact(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self._read_exact(8))[0]
        if n > MAX_FRAME:
            raise RuntimeError("frame too large")
        return opcode, self._read_exact(n)

    def close(self):
        if self.sock:
            try:
                self.sock.sendall(bytes((0x88, 0x80)) + os.urandom(4) + struct.pack("!H", 1000))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def stream(url, token=None, handler=None, seconds=None, session=None):
    """Open /v1/ws, optionally subscribe, and run handler(frame-dict) per frame."""
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    c = WSClient(url.replace("http://", "ws://").replace("https://", "wss://") + "/v1/ws", headers)
    c.connect()
    try:
        opcode, text = c.recv_message()
    except EOFError:
        c.close()
        return
    if handler:
        handler({"type": "hello", "data": text})
    if session:
        import json as _json
        c.send_text(_json.dumps({"op": "subscribe", "session": session}))
    start = time.time()
    try:
        while True:
            if seconds and time.time() - start >= seconds:
                return
            _, text = c.recv_message()
            if handler:
                handler({"type": "frame", "data": text})
    except (EOFError, OSError):
        pass
    finally:
        c.close()