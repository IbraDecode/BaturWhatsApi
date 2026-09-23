#!/usr/bin/env python3
"""BaturWhatsApi Python SDK example (stdlib only, Python 3.8+).

Talks to a running `batur serve` HTTP API (REST + SSE).

Usage:
    python3 batur_client.py --url http://127.0.0.1:8080 [--token SECRET] events
    python3 batur_client.py --url http://127.0.0.1:8080 sessions
    python3 batur_client.py --url http://127.0.0.1:8080 get mock-1
    python3 batur_client.py --url http://127.0.0.1:8080 text <session> <to_jid> <message>
"""
import argparse
import json
import sys
import urllib.request


class BaturClient:
    def __init__(self, url, token=None):
        self.url = url.rstrip("/")
        self.token = token

    def _req(self, method, path, body=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")

    def health(self):
        return self._req("GET", "/v1/health")

    def sessions(self):
        return self._req("GET", "/v1/sessions")["sessions"]

    def session(self, sid):
        return self._req("GET", "/v1/sessions/" + sid)

    def send_text(self, sid, to, text):
        return self._req("POST", "/v1/sessions/%s/text" % sid,
                         {"to": to, "text": text})

    def iq(self, sid, node, timeout="10s"):
        payload = dict(node)
        payload.setdefault("timeout", timeout)
        return self._req("POST", "/v1/sessions/%s/iq" % sid, payload)

    def events(self, handler, seconds=None):
        """Stream SSE events; handler(dict) called per event."""
        import time
        req = urllib.request.Request(self.url + "/v1/events")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        start = time.time()
        with urllib.request.urlopen(req) as resp:
            buf = {}
            for raw in resp:
                line = raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
                if line.startswith("event: "):
                    buf["event"] = line[7:]
                elif line.startswith("data: "):
                    buf["data"] = line[6:]
                elif line == "" and buf:
                    try:
                        handler({"event": buf.get("event"),
                                 "data": json.loads(buf.get("data", "{}"))})
                    except json.JSONDecodeError:
                        pass
                    buf = {}
                if seconds and time.time() - start > seconds:
                    return


def main():
    ap = argparse.ArgumentParser(description="BaturWhatsApi client example")
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    sub.add_parser("sessions")
    g = sub.add_parser("get"); g.add_argument("session")
    t = sub.add_parser("text"); t.add_argument("session"); t.add_argument("to"); t.add_argument("message")
    e = sub.add_parser("events"); e.add_argument("--seconds", type=int, default=None)
    args = ap.parse_args()
    c = BaturClient(args.url, args.token)

    if args.cmd == "health":
        print(json.dumps(c.health(), indent=2))
    elif args.cmd == "sessions":
        for s in c.sessions():
            print("%-16s %-14s account=%s retries=%d" %
                  (s["ID"], s["State"], s.get("Account", ""), s.get("Retries", 0)))
    elif args.cmd == "get":
        print(json.dumps(c.session(args.session), indent=2))
    elif args.cmd == "text":
        print(json.dumps(c.send_text(args.session, args.to, args.message), indent=2))
    elif args.cmd == "events":
        def show(ev):
            print("[%s] %s" % (ev["event"], json.dumps(ev["data"])[:160]))
        try:
            c.events(show, seconds=args.seconds)
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
