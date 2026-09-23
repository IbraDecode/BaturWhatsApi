package session

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"time"

	"github.com/ibradecode/baturwhatsapi/transport"
)

// recvCtx receives one frame with a fresh timeout, or ctx cancellation.
func recvCtx(ctx context.Context, conn transport.Conn, timeout time.Duration) ([]byte, error) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return conn.ReceiveBinary(rctx)
}

func sha1Short(data []byte) string {
	sum := sha256.Sum256(data)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
}

// recvTimeout helper for the handshake reader.
func recvTimeout(ctx context.Context, conn transport.Conn, timeout time.Duration) ([]byte, error) {
	return recvCtx(ctx, conn, timeout)
}
