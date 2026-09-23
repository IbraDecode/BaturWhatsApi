package api_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/e2e"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/storage"
)

func attach(t *testing.T, b *api.Batur, dialer mockserver.Dialer, srv *mockserver.Server, id string) {
	t.Helper()
	if err := b.Attach(id, dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web", DeviceName: id}); err != nil {
		t.Fatal(err)
	}
}

func waitOnline(t *testing.T, b *api.Batur, id string) api.SessionStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err := b.Status(id)
		if err == nil && st.State == api.StateOnline && st.Account != "" {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("session %s never ONLINE with account", id)
	return api.SessionStatus{}
}

// TestE2EMessageRelay exercises the full encrypted path:
// alice SendText -> Double Ratchet envelope -> noise transport ->
// mock server (recipient endpoint) decrypt -> plaintext push to bob ->
// bob's public OnMessage event.
func TestE2EMessageRelay(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	b, err := api.New(api.Options{
		Dict: dict,
		BundleSource: func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	attach(t, b, dialer, srv, "alice")
	attach(t, b, dialer, srv, "bob")

	type got struct {
		sess, from, text, id string
	}
	received := make(chan got, 8)
	b.Bus().MustSubscribe(events.MessageReceived, 32, events.PolicyBlock,
		func(_ context.Context, ev events.Event) {
			n, ok := ev.Data.(binary.Node)
			if !ok {
				return
			}
			child, ok := n.ChildByTag("plain")
			if !ok {
				return // never accept raw e2e nodes as delivered text
			}
			text, _ := child.TextContent()
			id, _ := n.StringAttr("id")
			received <- got{sess: ev.Session, from: n.MustStringAttr("from"), text: text, id: id}
		})
	sent := make(chan events.Event, 8)
	b.Bus().MustSubscribe(events.MessageSent, 32, events.PolicyBlock,
		func(_ context.Context, ev events.Event) { sent <- ev })

	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())

	alice := waitOnline(t, b, "alice")
	bob := waitOnline(t, b, "bob")

	msgID, err := b.SendText(ctx, "alice", api.Target{JID: bob.Account}, "halo bob, ini pesan terenkripsi")
	if err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if msgID == "" {
		t.Fatal("empty message id")
	}
	// Alice's MessageSent event.
	select {
	case ev := <-sent:
		if ev.Session != "alice" {
			t.Fatalf("sent event session = %s", ev.Session)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no message.sent event")
	}
	// Bob's delivered plaintext (skip server demo pushes).
	deadline := time.Now().Add(5 * time.Second)
	matched := false
	for time.Now().Before(deadline) && !matched {
		select {
		case g := <-received:
			if g.text == "halo bob, ini pesan terenkripsi" {
				if g.sess != "bob" {
					t.Fatalf("delivery session = %s", g.sess)
				}
				if g.from != alice.Account {
					t.Fatalf("from = %q want %q", g.from, alice.Account)
				}
				matched = true
			}
		default:
			time.Sleep(30 * time.Millisecond)
		}
	}
	if !matched {
		t.Fatal("bob never received the relayed message")
	}

	// Second message continues the ratchet (server must Decrypt, not init).
	_ = deadline
	if _, err := b.SendText(ctx, "alice", api.Target{JID: bob.Account}, "pesan kedua"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case g := <-received:
			if g.text == "pesan kedua" {
				return // ✔ continuation works
			}
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Fatal("ratchet continuation delivery missing")
}

func newFileStore(dir string) (*storage.FileStore, error) {
	return storage.NewFileStore(dir)
}

// TestRatchetStatePersisted ensures api-level persistence of e2e state.
func TestRatchetStatePersisted(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	store, err := newFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := api.New(api.Options{Dict: dict, Store: store,
		BundleSource: func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	attach(t, b, dialer, srv, "carol")
	var mu sync.Mutex
	seen := 0
	b.Bus().MustSubscribe(events.MessageReceived, 8, events.PolicyBlock,
		func(context.Context, events.Event) { mu.Lock(); seen++; mu.Unlock() })
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	carol := waitOnline(t, b, "carol")
	if _, err := b.SendText(ctx, "carol", api.Target{JID: carol.Account}, "self-loop"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := seen >= 1
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Verify storage got a ratchet entry.
	keys, _ := store.List(ctx, "session/carol/e2e/")
	if len(keys) != 1 {
		t.Fatalf("ratchet state not persisted: %v", keys)
	}
}
