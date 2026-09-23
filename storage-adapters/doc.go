// Package storageadapters is an optional sibling module for the
// BaturWhatsApi core. It provides KV adapters for engines that the
// core deliberately does not import (PostgreSQL, SQLite).
//
// Per ADR-0007 the core keeps its zero-dependency invariant; consumers
// who need an external store import this module explicitly and accept
// the supply-chain surface they bring in.
//
// Wire-up is one line at the call site:
//
//	import (
//	    "github.com/ibradecode/baturwhatsapi/storage"
//	    storeadapters "github.com/ibradecode/baturwhatsapi/storage-adapters/postgres"
//	)
//	opts.Store = storeadapters.NewPostgres(dsn)
//
// Real adapters return types that satisfy storage.KV. The constructors
// in this scaffold return ErrNotImplemented until the matching driver is
// chosen and the schema is written; pick the driver deliberately before
// enabling the adapter in production.
package storageadapters
