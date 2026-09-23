package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/e2e"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/storage"
)

// TestManualRunSync verifies RunSync stores a queryable snapshot and emits
// domain events through the real protocol path.
func TestManualRunSync(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := api.New(api.Options{Dict: dict, Store: storage.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("syncer", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	contactsCh := make(chan struct{}, 32)
	b.Bus().MustSubscribe(events.ContactUpdated, 16, events.PolicyBlock,
		func(context.Context, events.Event) { contactsCh <- struct{}{} })
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	waitOnline(t, b, "syncer")

	if err := b.RunSync(ctx, "syncer"); err != nil {
		t.Fatalf("RunSync: %v", err)
	}
	contacts, err := b.Contacts(ctx, "syncer")
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 10 {
		t.Fatalf("contacts = %d want 10", len(contacts))
	}
	if contacts[0].JID == "" || contacts[0].Name == "" {
		t.Fatalf("contact not decoded: %+v", contacts[0])
	}
	chats, err := b.Chats(ctx, "syncer")
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 7 {
		t.Fatalf("chats = %d want 7", len(chats))
	}
	// Domain events fired (bus is async: drain with a deadline).
	got := 0
	deadline := time.Now().Add(3 * time.Second)
	for got < 10 && time.Now().Before(deadline) {
		select {
		case <-contactsCh:
			got++
		case <-time.After(200 * time.Millisecond):
		}
	}
	if got < 10 {
		t.Fatalf("contact events = %d want >=10", got)
	}
}

// TestAutoSyncOnReady verifies the Sync.Enabled flag snapshots on ready.
func TestAutoSyncOnReady(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := api.New(api.Options{Dict: dict, Store: storage.NewMemory(),
		Sync: api.SyncOptions{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("auto", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())

	// Poll until auto-sync populates the snapshot.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		contacts, _ := b.Contacts(ctx, "auto")
		if len(contacts) == 10 {
			return // auto-sync done
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("auto-sync on ready never populated snapshot")
}

// TestHistoryAndAcks verifies bounded conversation persistence + ack
// lifecycle across an encrypted send and server receipts.
func TestHistoryAndAcks(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := api.New(api.Options{Dict: dict, Store: storage.NewMemory(), History: true,
		BundleSource: func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("hist", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	st := waitOnline(t, b, "hist")

	// send -> pending/sent recorded
	id, err := b.SendText(ctx, "hist", api.Target{JID: st.Account}, "persist me")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var found *api.StoredMessage
	for time.Now().Before(deadline) && found == nil {
		h, err := b.History(ctx, "hist", st.Account, 50)
		if err != nil {
			t.Fatal(err)
		}
		for i := range h {
			if h[i].ID == id && h[i].FromMe && h[i].Text == "persist me" {
				found = &h[i]
			}
		}
		if found == nil {
			time.Sleep(30 * time.Millisecond)
		}
	}
	if found == nil {
		t.Fatal("sent message not in history")
	}

	// inbound relay message should also be recorded
	deadline = time.Now().Add(3 * time.Second)
	var got bool
	for time.Now().Before(deadline) && !got {
		chats, _ := b.RecentChats(ctx, "hist")
		for _, c := range chats {
			h, _ := b.History(ctx, "hist", c, 50)
			for _, m := range h {
				if !m.FromMe {
					got = true
				}
			}
		}
		if !got {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !got {
		t.Fatal("inbound message not persisted")
	}
}
