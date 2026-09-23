package session_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/noise"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
)

func testServer(t *testing.T) (*mockserver.Server, mockserver.Dialer) {
	t.Helper()
	srv, err := mockserver.New(token.Default())
	if err != nil {
		t.Fatal(err)
	}
	return srv, mockserver.Dialer{Srv: srv}
}

func trustedAuth(t *testing.T, srv *mockserver.Server) session.ServerAuth {
	t.Helper()
	return func(staticPub, certBlob []byte) error {
		if len(staticPub) != 32 {
			return errors.New("bad static length")
		}
		if !strings.HasPrefix(string(certBlob), "mock-cert:") {
			return errors.New("untrusted cert blob")
		}
		return nil
	}
}

func newSession(t *testing.T, id string, dialer mockserver.Dialer, store storage.KV, bus *events.Bus, auth session.ServerAuth) *session.Session {
	t.Helper()
	s, err := session.New(session.Options{
		ID: id, Dialer: dialer, Dict: token.Default(), Store: store, Bus: bus,
		Device:    session.DeviceInfo{Platform: "web", DeviceName: "batur-test"},
		PingEvery: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.ServerAuth = auth
	return s
}

func TestSessionFullLifecycle(t *testing.T) {
	srv, dialer := testServer(t)
	ctx := context.Background()
	bus := events.New()
	defer bus.Close()
	ready := make(chan bool, 4)
	bus.MustSubscribe(events.SessionReady, 8, events.PolicyBlock,
		func(context.Context, events.Event) { ready <- true })
	msgCh := make(chan binary.Node, 8)
	bus.MustSubscribe(events.MessageReceived, 8, events.PolicyBlock,
		func(_ context.Context, ev events.Event) {
			if n, ok := ev.Data.(binary.Node); ok {
				select {
				case msgCh <- n:
				default:
				}
			}
		})

	store := storage.NewMemory()
	s := newSession(t, "dev-a", dialer, store, bus, trustedAuth(t, srv))
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if s.State() != statemachine.Online {
		t.Fatalf("state = %s want ONLINE", s.State())
	}
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("session.ready never emitted")
	}
	// Mock server proactively pushes a message: verify event pipeline.
	select {
	case n := <-msgCh:
		if n.Tag != "message" {
			t.Fatalf("msg tag = %q", n.Tag)
		}
		child, ok := n.ChildByTag("plain")
		if !ok {
			t.Fatal("no plain child")
		}
		if txt, _ := child.TextContent(); txt != "Hello from Batur mock server" {
			t.Fatalf("msg = %q", txt)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no proactive message")
	}

	// Demo echo IQ round trip.
	req := binary.Node{
		Tag: "iq", Attrs: binary.Attrs{"type": "get", "xmlns": "batur.demo"},
		Content: []binary.Node{{Tag: "echo", Attrs: binary.Attrs{"msg": "halo dun"}}},
	}
	resp, err := s.Request(ctx, req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	echo, ok := resp.ChildByTag("echo")
	if !ok || echo.MustStringAttr("msg") != "halo dun" {
		t.Fatalf("echo resp = %+v", resp)
	}

	// Credentials persisted.
	if _, err := store.Get(ctx, "session/dev-a/credentials"); err != nil {
		t.Fatalf("credentials not persisted: %v", err)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s.State() != statemachine.Stopped {
		t.Fatalf("after stop state = %s", s.State())
	}
}

func TestSessionResumeAcrossRestart(t *testing.T) {
	srv, dialer := testServer(t)
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := storage.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	s1 := newSession(t, "dev-b", dialer, fs, nil, trustedAuth(t, srv))
	if err := s1.Start(ctx); err != nil {
		t.Fatal(err)
	}
	acct1, _ := s1.Credentials().AccountJID, true
	if acct1 == "" {
		// account assigned async in connectIQ? ensure it lands
		for i := 0; i < 50 && s1.Credentials().AccountJID == ""; i++ {
			time.Sleep(20 * time.Millisecond)
		}
	}
	_ = s1.Stop(ctx)

	// "Process restart": brand new session object, same store.
	s2 := newSession(t, "dev-b", dialer, fs, nil, trustedAuth(t, srv))
	if err := s2.Start(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	defer s2.Stop(ctx)
	if s2.Credentials().RegistrationID != s1.Credentials().RegistrationID {
		t.Fatal("identity did not survive restart")
	}
	reg := srv.Registrations()[s2.DeviceID()]
	if reg.DeviceID == "" {
		t.Fatalf("server lost registration: %+v", srv.Registrations())
	}
	if string(s2.Credentials().ServerStatic) == "" {
		t.Fatal("server static key not persisted")
	}
}

func TestSessionRejectsUntrustedServer(t *testing.T) {
	_, dialer := testServer(t)
	ctx := context.Background()
	badAuth := func(staticPub, certBlob []byte) error {
		return errors.New("pin mismatch")
	}
	s := newSession(t, "dev-c", dialer, storage.NewMemory(), nil, badAuth)
	err := s.Start(ctx)
	if err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("expected auth failure, got %v", err)
	}
	if s.State() != statemachine.Error {
		t.Fatalf("state after auth reject = %s", s.State())
	}
}

func TestSessionMissingAuthPolicyFailsClosed(t *testing.T) {
	_, dialer := testServer(t)
	s, err := session.New(session.Options{
		ID: "dev-d", Dialer: dialer, Store: storage.NewMemory(),
		Device: session.DeviceInfo{Platform: "web"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("must refuse when ServerAuth unset, got %v", err)
	}
}

func TestSessionStaleRecoveryTriggersDisconnect(t *testing.T) {
	srv, dialer := testServer(t)
	srv.IgnoreAcks = true
	ctx := context.Background()
	bus := events.New()
	defer bus.Close()
	store := storage.NewMemory()
	s, err := session.New(session.Options{
		ID: "dev-e", Dialer: dialer, Store: store, Bus: bus,
		Device:    session.DeviceInfo{Platform: "web"},
		PingEvery: 60 * time.Millisecond, StaleAfter: 120 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.ServerAuth = trustedAuth(t, srv)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Block inbound by killing the pipe peer's ability to respond:
	// simplest failure injection is closing the connection from server side.
	done := s.Done()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session never terminated after going stale")
	}
	if s.State() == statemachine.Online {
		t.Fatal("stale session stayed ONLINE")
	}
	_ = s.Stop(context.Background())
}

// Compile-time sanity: noise keypair usable in sessions.
var _ = noise.NewKeyPair
