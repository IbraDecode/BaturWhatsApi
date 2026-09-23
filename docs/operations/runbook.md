# Operations runbook (24/7 runtime)

## Deployment model

Single binary `batur` + data directory:

```
bin/batur doctor            # self-check (keygen, codec, engine connect, e2e)
bin/batur demo              # in-process smoke (mock server)
bin/batur serve --mock --data /var/lib/batur --bind 127.0.0.1:8080
                            # REST+SSE API; sessions persist in --data
                            # BATUR_API_TOKEN env enables bearer auth (required
                            # for non-localhost binds)
```

Embedded usage (recommended today): import `api`, provide a
`transport.Dialer` (ws dialer for WhatsApp web endpoint, or your own
proxy), a storage dir, and a `ServerAuth` policy.

## Health & observability

- `Supervisor.Health()` → per-session state, retries, last-online.
- Event bus (`session.ready`, `connection.state`, `connection.error`,
  `supervisor.action`) is the machine-readable health stream; subscribe
  and export to your monitoring.
- Logs are structured `log/slog` (`session` attribute on all lines).

## Recovery behavior

- Any connection failure → supervisor backoff (base 1s, max 60s, ±20%
  jitter, resets after 2m stable) and full re-handshake with persisted
  credentials (resume).
- Inbound-silence watchdog (session.StaleAfter) marks DEGRADED, forces
  reconnect; supervisor watchdog force-retries a session stuck in a
  transient state > StuckThreshold.
- `batur.Stop(ctx)` sends `xmlstreamend`, closes sockets cleanly and
  waits for loops; state reaches STOPPED.

## Backups / secrets

- The data directory contains session credentials (X25519 seeds).
  Back it up encrypted; treat it as secret material.
- Rotation: stop sessions → move the dir; a session bound to a lost dir
  must re-register (new identity).

## Crash expectations

- Kill -9 mid-write: file store is atomic per key (temp+rename); worst
  case is losing the latest checkpoint, never a torn node.
- Session restart is automatic via supervisor loop; NO manual process
  restart should be required for recoverable failures. systemd:
  `Restart=always` as a second safety layer only.

## Upgrade / rollback

- Protocol dictionaries and wire behavior are versioned data + code;
  upgrades are drop-in binaries. Rollback = previous binary + same data
  dir (backward-compatible credential format from v0.1).
