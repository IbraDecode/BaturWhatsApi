package supervisor_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
	"github.com/ibradecode/baturwhatsapi/supervisor"
)

func trustAll() session.ServerAuth {
	return func([]byte, []byte) error { return nil }
}

func TestAutoReconnect(t *testing.T) {
	srv, err := mockserver.New(token.Default())
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	// Sever the connection after every 2nd IQ response (connect iq +
	// demo pings): guarantees periodic forced drops.
	srv.SetDropAfterRequests(2)

	bus := events.New()
	defer bus.Close()
	var mu sync.Mutex
	recovered := 0
	bus.MustSubscribe(events.SupervisorAction, 16, events.PolicyDropOldest,
		func(_ context.Context, ev events.Event) {
			mu.Lock()
			recovered++
			mu.Unlock()
		})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sv := supervisor.New(supervisor.Options{
		Bus: bus, Store: storage.NewMemory(),
		BaseBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
		StableReset: time.Second,
	})
	if err := sv.Add(supervisor.Config{
		Session: session.Options{ID: "s-a", Dialer: dialer, Dict: token.Default(),
			Device: session.DeviceInfo{Platform: "web"}, PingEvery: 100 * time.Millisecond},
		Auth: trustAll(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := sv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sv.Stop(context.Background())

	// Wait until at least one recovery happened and the session is ONLINE
	// again.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		r := recovered
		mu.Unlock()
		st := sv.Health()["s-a"]
		if r >= 1 && st.State == statemachine.Online {
			return // recovered ✔
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("never recovered: retries=%d actions=%d", sv.Health()["s-a"].Retries, recovered)
}

func TestMultiSessionIsolation(t *testing.T) {
	srv, err := mockserver.New(token.Default())
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	store, err := storage.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sv := supervisor.New(supervisor.Options{Store: store,
		BaseBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond})
	for _, id := range []string{"alpha", "beta", "gamma"} {
		if err := sv.Add(supervisor.Config{
			Session: session.Options{ID: id, Dialer: dialer, Dict: token.Default(),
				Device:    session.DeviceInfo{Platform: "web", DeviceName: id},
				PingEvery: 200 * time.Millisecond},
			Auth: trustAll(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sv.Stop(context.Background())

	// All three should reach ONLINE.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		h := sv.Health()
		if len(h) == 3 && h["alpha"].State == statemachine.Online &&
			h["beta"].State == statemachine.Online && h["gamma"].State == statemachine.Online {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	h := sv.Health()
	for id, st := range h {
		if st.State != statemachine.Online {
			t.Fatalf("session %s state = %s", id, st.State)
		}
	}
	// Each session has its own device credentials.
	seen := map[string]bool{}
	for _, st := range h {
		if st.Creds.RegistrationID == 0 {
			t.Fatal("missing registration id")
		}
		if seen[string(st.Creds.NoiseKeySeed[:16])] {
			t.Fatal("two sessions share noise keys")
		}
		seen[string(st.Creds.NoiseKeySeed[:16])] = true
	}
	// Server registered 3 distinct devices.
	if len(srv.Registrations()) != 3 {
		t.Fatalf("server registrations = %d", len(srv.Registrations()))
	}
}

func TestSupervisorRejectsEmptyFleet(t *testing.T) {
	sv := supervisor.New(supervisor.Options{})
	if err := sv.Start(context.Background()); err == nil {
		t.Fatal("expected error for empty fleet")
	}
}
