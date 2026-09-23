// Package transport defines the byte-frame transport contract for the
// protocol engine plus dependency-free implementations: an in-memory pipe
// (tests, embedded mode) and a WebSocket client (RFC 6455, wss/wss).
package transport

import (
	"context"
	"errors"
)

// ErrClosed is returned once the connection is shut down.
var ErrClosed = errors.New("transport: connection closed")

// Conn is a reliable ordered binary frame channel.
type Conn interface {
	// SendBinary writes one complete frame.
	SendBinary(ctx context.Context, frame []byte) error
	// ReceiveBinary blocks for the next frame (empty slice or error after
	// Close).
	ReceiveBinary(ctx context.Context) ([]byte, error)
	// BindingHeader returns bytes both peers agree on for the noise
	// handshake (e.g. HTTP request/response headers), or nil.
	BindingHeader() []byte
	// Close terminates the connection.
	Close() error
}

// Dialer establishes Conn values.
type Dialer interface {
	Dial(ctx context.Context, url string) (Conn, error)
}
