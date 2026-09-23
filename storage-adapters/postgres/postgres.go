// Package postgres contains a PostgreSQL KV adapter for the
// BaturWhatsApi core (storage.KV). It is a stub: the constructor
// returns ErrNotImplemented until a driver is chosen and the schema
// is written.
//
// Choosing the driver: pick one (pgx, lib/pq, ...) deliberately, add
// it to this module's go.mod, and replace the body of NewPostgres.
// The schema needs at minimum:
//
//	CREATE TABLE batur_kv (
//	    key   TEXT PRIMARY KEY,
//	    value BYTEA NOT NULL
//	);
//
// Implement the five storage.KV methods against that schema (Get, Set,
// Delete, List, and any future additions). Use context.Context for
// cancellation; never block past the deadline.
//
// Security: pair with a TLS-only DSN, a least-privilege role, and the
// AES-256-GCM at-rest sealing provided by storage.NewSecureKV on top of
// this adapter if the deployment requires it.
package postgres

import (
	"errors"

	"github.com/ibradecode/baturwhatsapi/storage"
)

// ErrNotImplemented is returned by the stub constructor until the
// driver is wired in. Replace once the driver is chosen.
var ErrNotImplemented = errors.New("storage-adapters/postgres: not implemented yet (choose driver, add go.mod dep, write schema)")

// NewPostgres returns a Postgres-backed storage.KV. Stub.
func NewPostgres(dsn string) (storage.KV, error) {
	_ = dsn
	return nil, ErrNotImplemented
}
