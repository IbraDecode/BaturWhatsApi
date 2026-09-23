package events

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func wait(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}

func TestOrdering(t *testing.T) {
	b := New()
	defer b.Close()
	var mu sync.Mutex
	var got []uint64
	b.MustSubscribe("message.*", 128, PolicyBlock, func(_ context.Context, ev Event) {
		mu.Lock()
		got = append(got, ev.Seq)
		mu.Unlock()
	})
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if err := b.Publish(ctx, Event{Type: "message.received"}); err != nil {
			t.Fatal(err)
		}
	}
	wait(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 100
	}, "not all events delivered")
	mu.Lock()
	defer mu.Unlock()
	for i, seq := range got {
		if seq != uint64(i+1) {
			t.Fatalf("out of order at %d: %d", i, seq)
		}
	}
}

func TestWildcards(t *testing.T) {
	b := New()
	defer b.Close()
	var conn, all atomic.Int64
	b.MustSubscribe("connection.*", 8, PolicyDropOldest, func(context.Context, Event) { conn.Add(1) })
	b.MustSubscribe("*", 8, PolicyDropOldest, func(context.Context, Event) { all.Add(1) })
	ctx := context.Background()
	_ = b.Publish(ctx, Event{Type: "connection.state"})
	_ = b.Publish(ctx, Event{Type: "message.received"})
	wait(t, 2*time.Second, func() bool { return all.Load() == 2 && conn.Load() == 1 },
		"pattern routing wrong")
}

func TestBackpressureBlock(t *testing.T) {
	b := New()
	defer b.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	b.MustSubscribe("slow", 1, PolicyBlock, func(context.Context, Event) {
		once.Do(func() { close(entered) })
		<-release
	})
	ctx := context.Background()
	if err := b.Publish(ctx, Event{Type: "slow"}); err != nil {
		t.Fatal(err)
	}
	<-entered                                                   // handler is now stuck consuming slot 1
	if err := b.Publish(ctx, Event{Type: "slow"}); err != nil { // fills the queue
		t.Fatal(err)
	}
	third := make(chan error, 1)
	go func() { third <- b.Publish(ctx, Event{Type: "slow"}) }()
	select {
	case err := <-third:
		t.Fatalf("third publish should have blocked: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-third:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked publish never completed")
	}
	wait(t, 2*time.Second, func() bool { return b.Stats().Delivered == 3 }, "events lost under backpressure")
}

func TestDropOldest(t *testing.T) {
	b := New()
	defer b.Close()
	block := make(chan struct{})
	var got atomic.Int64
	b.MustSubscribe("burst", 2, PolicyDropOldest, func(context.Context, Event) {
		<-block
		got.Add(1)
	})
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := b.Publish(ctx, Event{Type: "burst"}); err != nil {
			t.Fatal(err)
		}
	}
	if st := b.Stats(); st.Dropped < 8 {
		t.Fatalf("expected drops, stats: %s", st)
	}
	close(block)
	wait(t, 2*time.Second, func() bool { return got.Load() >= 2 }, "handler starvation")
}

func TestPanicIsolation(t *testing.T) {
	b := New()
	defer b.Close()
	var panicked atomic.Value
	b.OnPanic = func(id uint64, r any) { panicked.Store(r) }
	var ok atomic.Int64
	b.MustSubscribe("boom", 4, PolicyBlock, func(context.Context, Event) {
		panic("kaboom")
	})
	b.MustSubscribe("boom", 4, PolicyBlock, func(context.Context, Event) { ok.Add(1) })
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := b.Publish(ctx, Event{Type: "boom"}); err != nil {
			t.Fatal(err)
		}
	}
	wait(t, 2*time.Second, func() bool { return ok.Load() == 3 }, "healthy subscriber starved by panic")
	if panicked.Load() == nil {
		t.Fatal("OnPanic not invoked")
	}
	if b.Stats().Panics != 3 {
		t.Fatalf("panic counter = %d", b.Stats().Panics)
	}
}

func TestUnsubscribe(t *testing.T) {
	b := New()
	defer b.Close()
	var n atomic.Int64
	sub, err := b.Subscribe("x", 4, PolicyBlock, func(context.Context, Event) { n.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Publish(context.Background(), Event{Type: "x"})
	wait(t, 2*time.Second, func() bool { return n.Load() == 1 }, "no delivery")
	sub.Unsubscribe()
	_ = b.Publish(context.Background(), Event{Type: "x"})
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatalf("unsubscribed handler still running: %d", n.Load())
	}
}

func TestPublishAfterClose(t *testing.T) {
	b := New()
	b.MustSubscribe("*", 2, PolicyBlock, func(context.Context, Event) {})
	b.Close()
	if err := b.Publish(context.Background(), Event{Type: "x"}); err != ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
