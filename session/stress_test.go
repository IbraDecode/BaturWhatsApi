package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/storage"
)

func TestConnectCycleStress(t *testing.T) {
	srv, dialer := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fails := 0
	for i := 0; i < 30; i++ {
		s, err := session.New(session.Options{ID: "cyc", Dialer: dialer, Store: storage.NewMemory(),
			Dict: token.Default(), Device: session.DeviceInfo{Platform: "web"}})
		if err != nil {
			t.Fatal(err)
		}
		s.ServerAuth = func([]byte, []byte) error { return nil }
		if err := s.Start(ctx); err != nil {
			fails++
			t.Errorf("cycle %d start: %v", i, err)
			if fails > 2 {
				t.FailNow()
			}
			continue
		}
		s.Stop(ctx)
	}
	t.Logf("30 cycles done, fails=%d (srv %d regs)", fails, len(srv.Registrations()))
}
