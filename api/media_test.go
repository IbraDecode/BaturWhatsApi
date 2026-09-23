package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/storage"
)

// TestMediaInbound verifies a media (image) message pushed by the mock
// surfaces as a Message carrying parsed Media metadata, and persists in
// history when enabled.
func TestMediaInbound(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	srv.MediaDemo = true
	dialer := mockserver.Dialer{Srv: srv}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := api.New(api.Options{Dict: dict, Store: storage.NewMemory(), History: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("media-dev", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	found := make(chan api.Message, 4)
	if _, err := b.OnMessage(ctx, "media-dev", func(_ context.Context, m api.Message) {
		if m.Media != nil {
			select {
			case found <- m:
			default:
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	waitOnline(t, b, "media-dev")

	var got api.Message
	select {
	case got = <-found:
	case <-time.After(5 * time.Second):
		t.Fatal("media message never arrived")
	}
	if got.Type != "image" || got.Media == nil {
		t.Fatalf("not an image message: type=%q media=%+v", got.Type, got.Media)
	}
	if got.Media.Kind != "image" || got.Media.MIME != "image/jpeg" || got.Media.Caption != "Batur demo snapshot" {
		t.Fatalf("media not decoded: %+v", got.Media)
	}
	if got.Media.URL != "https://mock.local/media/batur-demo.jpg" {
		t.Fatalf("media url = %q", got.Media.URL)
	}
	if got.Media.Width != "640" || got.Media.Height != "480" {
		t.Fatalf("media dimensions not decoded: %+v", got.Media)
	}

	// History should expose the media metadata too.
	h, err := b.History(ctx, "media-dev", got.Chat.JID, 10)
	if err != nil {
		t.Fatal(err)
	}
	// History subs run on their own bus goroutine: poll briefly.
	var stored *api.StoredMessage
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h, err = b.History(ctx, "media-dev", got.Chat.JID, 10)
		if err != nil {
			t.Fatal(err)
		}
		for i := range h {
			if h[i].Media != nil {
				stored = &h[i]
				break
			}
		}
		if stored != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stored == nil {
		t.Fatal("media message missing from history")
	}
	if stored.Media.Kind != "image" || stored.Media.Caption != "Batur demo snapshot" {
		t.Fatalf("history media not decoded: %+v", stored.Media)
	}
}
