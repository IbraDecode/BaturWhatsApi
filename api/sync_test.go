package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/storage"
	batusync "github.com/ibradecode/baturwhatsapi/sync"
)

// TestSyncOverProtocol drives the resumable sync runner through the real
// encrypted protocol path (session IQ -> mock server pages -> checkpoints).
func TestSyncOverProtocol(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	store := storage.NewMemory()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := api.New(api.Options{Dict: dict, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("synctest", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	var syncEvents int
	done := make(chan events.Event, 8)
	b.Bus().MustSubscribe("sync.*", 8, events.PolicyBlock,
		func(_ context.Context, ev events.Event) {
			select {
			case done <- ev:
			default:
			}
		})
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	waitOnline(t, b, "synctest")

	r := &batusync.Runner{Session: "synctest", Store: store, Bus: b.Bus()}
	r.Stages = []batusync.Stage{
		{Name: "contacts", Fetch: syncFetch(b, "synctest", "contacts")},
		{Name: "chats", Fetch: syncFetch(b, "synctest", "chats")},
	}
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	prog := map[string]batusync.Checkpoint{}
	for _, cp := range r.Progress(ctx) {
		prog[cp.Stage] = cp
	}
	if !prog["contacts"].Complete || prog["contacts"].Items != 10 {
		t.Fatalf("contacts: %+v", prog["contacts"])
	}
	if !prog["chats"].Complete || prog["chats"].Items != 7 {
		t.Fatalf("chats: %+v", prog["chats"])
	}
	// Drain async bus events: started + completed must arrive.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			syncEvents++
		default:
			time.Sleep(20 * time.Millisecond)
		}
		if syncEvents >= 2 {
			break
		}
	}
	if syncEvents < 2 {
		t.Fatalf("sync events = %d", syncEvents)
	}
	// Re-run: everything complete -> zero fetches, immediate return.
	r2 := &batusync.Runner{Session: "synctest", Store: store, Bus: b.Bus()}
	r2.Stages = []batusync.Stage{
		{Name: "contacts", Fetch: func(context.Context, string) (batusync.Page, error) {
			t.Fatal("must not refetch completed stage")
			return batusync.Page{}, nil
		}},
		{Name: "chats", Fetch: func(context.Context, string) (batusync.Page, error) {
			t.Fatal("must not refetch completed stage")
			return batusync.Page{}, nil
		}},
	}
	if err := r2.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

// syncFetch builds a StageFunc that pages the mock sync endpoint.
func syncFetch(b *api.Batur, sessionID, stage string) batusync.StageFunc {
	return func(ctx context.Context, cursor string) (batusync.Page, error) {
		resp, err := b.RequestNode(ctx, sessionID, binary.Node{
			Tag: "iq",
			Attrs: binary.Attrs{
				"type": "get", "xmlns": "batur.sync", "stage": stage, "cursor": cursor,
			},
		})
		if err != nil {
			return batusync.Page{}, err
		}
		syncNode, ok := resp.ChildByTag("sync")
		if !ok {
			return batusync.Page{}, context.DeadlineExceeded
		}
		page := batusync.Page{}
		for _, item := range syncNode.Children() {
			page.Items = append(page.Items, item.MustStringAttr("id"))
		}
		page.Cursor = syncNode.MustStringAttr("cursor")
		return page, nil
	}
}
