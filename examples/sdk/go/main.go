// Command sdk-demo embeds BaturWhatsApi as a library: two sessions
// (alice, bob) against the in-process mock relay exchange an encrypted
// e2e message and print delivery events.
//
//	go run ./examples/sdk/go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		return err
	}
	dialer := mockserver.Dialer{Srv: srv}

	b, err := api.New(api.Options{
		Dict:  dict,
		Store: storage.NewMemory(),
		BundleSource: func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		},
	})
	if err != nil {
		return err
	}

	delivered := make(chan api.Message, 8)
	b.Bus().MustSubscribe(events.MessageReceived, 32, events.PolicyBlock,
		func(_ context.Context, ev events.Event) {
			n, ok := ev.Data.(binary.Node)
			if !ok {
				return
			}
			child, ok := n.ChildByTag("plain")
			if !ok {
				return
			}
			text, _ := child.TextContent()
			id, _ := n.StringAttr("id")
			delivered <- api.Message{ID: id, Text: text, Chat: api.Target{JID: n.MustStringAttr("from")}}
		})

	if err := b.Attach("alice", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web", DeviceName: "alice"}); err != nil {
		return err
	}
	if err := b.Attach("bob", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web", DeviceName: "bob"}); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Start(ctx); err != nil {
		return err
	}
	defer b.Stop(context.Background())

	bob := waitAccount(ctx, b, "bob")
	fmt.Println("bob online as", bob)

	msgID, err := b.SendText(ctx, "alice", api.Target{JID: bob}, "Halo Bob! (terenkripsi end-to-end)")
	if err != nil {
		return err
	}
	fmt.Println("alice sent message", msgID)

	select {
	case m := <-delivered:
		fmt.Printf("bob received %s from %s: %s\n", m.ID, m.Chat.JID, m.Text)
	case <-time.After(10 * time.Second):
		return fmt.Errorf("no delivery")
	}
	fmt.Println("SDK demo complete — engine is library-embeddable end-to-end")
	os.Stdout.Sync()
	return nil
}

func waitAccount(ctx context.Context, b *api.Batur, id string) string {
	for i := 0; i < 200; i++ {
		st, err := b.Status(id)
		if err == nil && st.State == api.StateOnline && st.Account != "" {
			return st.Account
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(50 * time.Millisecond):
		}
	}
	return ""
}
