# BaturWhatsApi 24/7 deployment kit (T-207)

Run one or more `batur serve` instances behind a TLS-terminating reverse
proxy. The engine is a single static binary with zero runtime deps, so
deployment is: copy the binary, generate a master key, install the unit.

## 1. Install the binary

```sh
sudo install -m 0755 batur-linux-amd64 /usr/local/bin/batur
```

## 2. Secrets (fail-closed)

```sh
sudo mkdir -p /etc/batur /var/lib/batur
batur keygen > /tmp/key                       # 64-hex master key
sudo install -m 0600 /tmp/key /etc/batur/master.key
sudo install -m 0600 /dev/null /etc/batur/env
cat > /etc/batur/env <<'EOF'
BATUR_API_TOKEN=change-me-strong-value
# BATUR_MASTER_KEY=...  # alternative to --seal-key-file
EOF
sudo chmod 0600 /etc/batur/env
```

Data in `/var/lib/batur` is sealed (AES-256-GCM, `bseal1:` internally). If
the master key is lost or wrong, sessions fail closed (they do NOT regenerate
fresh identities that peers would then distrust).

## 3. Run as a service

```sh
sudo install -m 0644 batur.service /etc/systemd/system/batur.service
sudo systemctl daemon-reload
sudo systemctl enable --now batur
journalctl -u batur -f        # logs
curl http://127.0.0.1:8080/v1/health
```

## 4. Expose behind TLS

The API server speaks plain HTTP with a bearer token (`BATUR_API_TOKEN`
required for any non-localhost bind — starting with a non-local bind without
a token is refused). Terminate TLS at the proxy and forward `/v1/*`,
`/metrics`, and the WebSocket upgrade `GET /v1/ws`:

```nginx
location /v1/ws {
  proxy_pass http://127.0.0.1:8080;
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
}
```

WS `/v1/ws` is plain `ws:` end-to-end inside the network; the ws package
does not implement permessage-deflate (see `docs/KNOWN_ISSUES.md`).

## 5. Observability

- `curl http://127.0.0.1:8080/metrics` — Prometheus text format.
- `GET /v1/health` — engine + bus stats.
- SDKs under `examples/sdk/` subscribe to `/v1/ws` (real-time events:
  `message.sent`, `session.ready`, `sync.completed`, acks, ...).