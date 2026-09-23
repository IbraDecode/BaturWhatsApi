// Package bench measures the engine's runtime economics:
// codec throughput, crypto cost, per-session idle footprint, and
// end-to-end request throughput against the in-process mock server.
// Run: go test -bench=. -benchmem -run '^$' ./internal/bench
package bench

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/storage"
)

func sampleHeap() (heapAlloc uint64, goroutines int) {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc, runtime.NumGoroutine()
}

func testNode() binary.Node {
	return binary.Node{Tag: "message", Attrs: binary.Attrs{
		"from": "628123456789@s.whatsapp.net",
		"id":   "ABCDEF1234567890",
		"type": "text",
		"t":    "1690000000",
	}, Content: []binary.Node{{
		Tag:     "plain",
		Content: "The quick brown fox jumps over the lazy dog — benchmark payload.",
	}}}
}

func BenchmarkNodeEncode(b *testing.B) {
	dict := token.Default()
	n := testNode()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = binary.MarshalDict(n, dict)
	}
}

func BenchmarkNodeDecode(b *testing.B) {
	dict := token.Default()
	raw := binary.Marshal(testNode())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := binary.Decode(dict, raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshake(b *testing.B) {
	srv, err := mockserver.New(token.Default())
	if err != nil {
		b.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	auth := session.TrustedRootAuth(srv.RootPub())
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := session.New(session.Options{
			ID: fmt.Sprintf("bench-%d", i), Dialer: dialer, Store: storage.NewMemory(),
			Device:    session.DeviceInfo{Platform: "web"},
			PingEvery: time.Hour,
		})
		if err != nil {
			b.Fatal(err)
		}
		s.ServerAuth = auth
		if err := s.Start(ctx); err != nil {
			b.Fatal(err)
		}
		_ = s.Stop(ctx)
	}
}

// TestSessionFootprint asserts the idle-memory design goal quantitatively
// and fails CI if sessions regress dramatically.
func TestSessionFootprint(t *testing.T) {
	const n = 100
	srv, err := mockserver.New(token.Default())
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	auth := session.TrustedRootAuth(srv.RootPub())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseHeap, baseGor := sampleHeap()
	sessions := make([]*session.Session, 0, n)
	defer func() {
		for _, s := range sessions {
			_ = s.Stop(context.Background())
		}
	}()
	for i := 0; i < n; i++ {
		s, err := session.New(session.Options{
			ID: fmt.Sprintf("fp-%d", i), Dialer: dialer, Store: storage.NewMemory(),
			Device:    session.DeviceInfo{Platform: "web", DeviceName: "fp"},
			PingEvery: 10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		s.ServerAuth = auth
		if err := s.Start(ctx); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		sessions = append(sessions, s)
	}
	// Idle settle: stop keepalives churn by waiting one quiet window.
	time.Sleep(200 * time.Millisecond)
	heapAfter, gorAfter := sampleHeap()

	perSessionBytes := float64(heapAfter-baseHeap) / float64(n)
	t.Logf("sessions=%d heap %d -> %d bytes (%.1f KiB/session idle) goroutines %d -> %d",
		n, baseHeap, heapAfter, perSessionBytes/1024, baseGor, gorAfter)

	// Regression budget: < 512 KiB heap per idle session on this stack.
	if perSessionBytes > 512*1024 {
		t.Fatalf("idle footprint regressed: %.0f bytes/session (>512KiB)", perSessionBytes)
	}
	// Engine goroutines per session: reader + consumer + keepalive = ~3.
	if perG := float64(gorAfter-baseGor) / float64(n); perG > 6 {
		t.Fatalf("goroutine leak: %.2f/session (>6)", perG)
	}
}

// TestThroughput measures request/response round trips (decode+encode+cipher
// per hop) to keep a published baseline number in CI logs.
func TestThroughput(t *testing.T) {
	srv, err := mockserver.New(token.Default())
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := session.New(session.Options{ID: "tp", Dialer: dialer, Store: storage.NewMemory(),
		Device: session.DeviceInfo{Platform: "web"}, PingEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s.ServerAuth = session.TrustedRootAuth(srv.RootPub())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())

	const rounds = 3000
	start := time.Now()
	for i := 0; i < rounds; i++ {
		req := binary.Node{
			Tag: "iq", Attrs: binary.Attrs{"type": "get", "xmlns": "batur.demo"},
			Content: []binary.Node{{Tag: "echo", Attrs: binary.Attrs{"msg": fmt.Sprintf("m-%d", i)}}},
		}
		resp, err := s.Request(ctx, req)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		echo, ok := resp.ChildByTag("echo")
		if !ok {
			t.Fatalf("round %d: no echo", i)
		}
		if got := echo.MustStringAttr("msg"); got != fmt.Sprintf("m-%d", i) {
			t.Fatalf("round %d echo = %q", i, got)
		}
	}
	elapsed := time.Since(start)
	t.Logf("%d encrypted iq round trips in %v (%.0f/s; %.0f us/op)",
		rounds, elapsed.Round(time.Millisecond), float64(rounds)/elapsed.Seconds(),
		float64(elapsed.Microseconds())/float64(rounds))
}
