// Package sqlite contains a SQLite KV adapter for the BaturWhatsApi
// core (storage.KV). Stub: see postgres.go for the same shape.
//
// Choosing the driver: pick one (modernc.org/sqlite for pure Go, or
// mattn/go-sqlite3 for cgo) deliberately, add it to this module's
// go.mod, and replace the body of NewSQLite.
package sqlite

import (
	"errors"

	"github.com/ibradecode/baturwhatsapi/storage"
)

// ErrNotImplemented mirrors the postgres stub.
var ErrNotImplemented = errors.New("storage-adapters/sqlite: not implemented yet (choose driver, add go.mod dep, write schema)")

// NewSQLite returns a SQLite-backed storage.KV. Stub.
func NewSQLite(path string) (storage.KV, error) {
	_ = path
	return nil, ErrNotImplemented
}
