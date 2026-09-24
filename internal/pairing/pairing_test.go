package pairing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/session"
)

func TestPairMockRoundTrip(t *testing.T) {
	srv, err := mockserver.New(token.Default())
	if err != nil {
		t.Fatal(err)
	}
	var sawQR bool
	res, err := Pair(context.Background(), PairingConfig{
		EdgeServer: "mock://pair",
		DeviceID:   "dev-1",
		DeviceName: "batur-test",
		Platform:   "web",
		Dialer:     mockserver.Dialer{Srv: srv},
		ServerAuth: session.TrustedRootAuth(srv.RootPub()),
		QRTimeout:  5 * time.Second,
		QRCallback: func(code, ref string, exp time.Time) error {
			if code == "" || ref == "" || exp.IsZero() {
				t.Errorf("incomplete qr code=%q ref=%q exp=%v", code, ref, exp)
			}
			sawQR = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawQR {
		t.Fatal("qr callback not invoked")
	}
	if res.AccountJID == "" || res.DeviceID != "dev-1" {
		t.Fatalf("result %+v", res)
	}
	if len(res.NoiseKeySeed) != 32 || len(res.ServerStatic) != 32 || len(res.CertChain) == 0 {
		t.Fatalf("missing key material seed=%d static=%d cert=%d",
			len(res.NoiseKeySeed), len(res.ServerStatic), len(res.CertChain))
	}
	if err := session.TrustedRootAuth(srv.RootPub())(res.ServerStatic, res.CertChain); err != nil {
		t.Fatal(err)
	}
}

func TestPairRequiresAuth(t *testing.T) {
	_, err := Pair(context.Background(), PairingConfig{Dialer: mockserver.Dialer{}})
	if err == nil {
		t.Fatal("expected fail-closed without ServerAuth")
	}
}

func TestPairQRCancel(t *testing.T) {
	srv, err := mockserver.New(token.Default())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Pair(context.Background(), PairingConfig{
		DeviceID:   "dev-cancel",
		Dialer:     mockserver.Dialer{Srv: srv},
		ServerAuth: session.TrustedRootAuth(srv.RootPub()),
		QRTimeout:  5 * time.Second,
		QRCallback: func(string, string, time.Time) error {
			return errors.New("user closed")
		},
	})
	if !errors.Is(err, ErrPairingCancelled) {
		t.Fatalf("got %v", err)
	}
}
