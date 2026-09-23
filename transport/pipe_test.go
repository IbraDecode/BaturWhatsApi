package transport

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestPipeBasics(t *testing.T) {
	client, server := Pipe([]byte("BIND"))
	ctx := context.Background()
	if got := string(client.BindingHeader()); got != "BIND" {
		t.Fatalf("binding = %q", got)
	}
	if err := client.SendBinary(ctx, []byte("frame1")); err != nil {
		t.Fatal(err)
	}
	got, err := server.ReceiveBinary(ctx)
	if err != nil || !bytes.Equal(got, []byte("frame1")) {
		t.Fatalf("server got %q %v", got, err)
	}
	if err := server.SendBinary(ctx, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	got, err = client.ReceiveBinary(ctx)
	if err != nil || !bytes.Equal(got, []byte("pong")) {
		t.Fatalf("client got %q %v", got, err)
	}
}

func TestPipeCloseAndCtx(t *testing.T) {
	client, server := Pipe(nil)
	ctx := context.Background()
	if err := client.SendBinary(ctx, []byte("x")); err != nil {
		t.Fatal(err)
	}
	client.Close()
	// Buffered frames still readable after close.
	if _, err := server.ReceiveBinary(ctx); err != nil {
		t.Fatalf("buffered read after close: %v", err)
	}
	if _, err := server.ReceiveBinary(ctx); err != ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
	// Sending to a closed peer fails fast.
	dctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := server.SendBinary(dctx, []byte("y")); err != ErrClosed {
		t.Fatalf("expected ErrClosed on send, got %v", err)
	}
}

func TestPipeBackpressure(t *testing.T) {
	client, server := Pipe(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// Queue holds 64; the 65th send must block until we drain.
	var err error
	for i := 0; i < 64 && err == nil; i++ {
		err = client.SendBinary(ctx, []byte("f"))
	}
	if err != nil {
		t.Fatalf("64 sends failed early: %v", err)
	}
	if err = client.SendBinary(ctx, []byte("f")); err == nil {
		t.Fatal("65th send should have blocked")
	}
	// Drain unblocks.
	go func() {
		for i := 0; i < 2; i++ {
			_, _ = server.ReceiveBinary(context.Background())
		}
	}()
	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dcancel()
	if err := client.SendBinary(dctx, []byte("f")); err != nil {
		t.Fatalf("blocked send never drained: %v", err)
	}
}
