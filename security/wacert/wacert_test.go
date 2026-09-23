package wacert

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/protocol/pb"
)

type world struct {
	rootPub   ed25519.PublicKey
	rootPriv  ed25519.PrivateKey
	interPub  ed25519.PublicKey
	interPriv ed25519.PrivateKey
	serverKey []byte // noise static (leaf key)
	now       time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{now: time.Now()}
	w.rootPub, w.rootPriv, _ = ed25519.GenerateKey(rand.Reader)
	w.interPub, w.interPriv, _ = ed25519.GenerateKey(rand.Reader)
	w.serverKey = make([]byte, 32)
	if _, err := rand.Read(w.serverKey); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) chain(t *testing.T, leafKey []byte, leafSerial, leafIssuer, interSerial uint32,
	leafValid, interValid [2]time.Time, signRoot, signInter ed25519.PrivateKey) []byte {
	t.Helper()
	leafDetails := BuildDetails(leafSerial, leafIssuer, leafKey, leafValid[0], leafValid[1])
	interDetails := BuildDetails(interSerial, RootSerial, w.interPub, interValid[0], interValid[1])
	return BuildChain(
		leafDetails, ed25519.Sign(signInter, leafDetails),
		interDetails, ed25519.Sign(signRoot, interDetails))
}

func (w *world) valid(t *testing.T) []byte {
	return w.chain(t, w.serverKey, 7, 3, 3,
		[2]time.Time{w.now.Add(-time.Hour), w.now.Add(time.Hour)},
		[2]time.Time{w.now.Add(-time.Hour), w.now.Add(24 * time.Hour)},
		w.rootPriv, w.interPriv)
}

func TestVerifyHappy(t *testing.T) {
	w := newWorld(t)
	if err := Verify(w.valid(t), w.serverKey, w.rootPub, w.now); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	w := newWorld(t)
	future := [2]time.Time{w.now.Add(-time.Hour), w.now.Add(time.Hour)}
	validInter := [2]time.Time{w.now.Add(-time.Hour), w.now.Add(24 * time.Hour)}

	cases := []struct {
		name  string
		chain []byte
		key   []byte
		root  ed25519.PublicKey
		when  time.Time
	}{
		{"wrong root", w.valid(t), w.serverKey, mustOtherRoot(t), w.now},
		{"leaf expired", w.chain(t, w.serverKey, 7, 3, 3,
			[2]time.Time{w.now.Add(-2 * time.Hour), w.now.Add(-time.Hour)},
			validInter, w.rootPriv, w.interPriv), w.serverKey, w.rootPub, w.now},
		{"not yet valid", w.chain(t, w.serverKey, 7, 3, 3, future, validInter,
			w.rootPriv, w.interPriv), w.serverKey, w.rootPub, w.now.Add(-48 * time.Hour)},
		{"inter expired", w.chain(t, w.serverKey, 7, 3, 3, future,
			[2]time.Time{w.now.Add(-2 * time.Hour), w.now.Add(-time.Hour)},
			w.rootPriv, w.interPriv), w.serverKey, w.rootPub, w.now},
		{"key mismatch", w.valid(t), make([]byte, 32), w.rootPub, w.now},
		{"serial mismatch", w.chain(t, w.serverKey, 8, 4, 3, future, validInter,
			w.rootPriv, w.interPriv), w.serverKey, w.rootPub, w.now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(tc.chain, tc.key, tc.root, tc.when); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestVerifyTamper(t *testing.T) {
	w := newWorld(t)
	good := w.valid(t)
	// Flip a byte inside the leaf signature region.
	bad := append([]byte{}, good...)
	bad[len(bad)-10] ^= 0x40
	if err := Verify(bad, w.serverKey, w.rootPub, w.now); err == nil {
		t.Fatal("tampered chain accepted")
	}
	if err := Verify([]byte{0xFF, 0xFF}, w.serverKey, w.rootPub, w.now); err == nil {
		t.Fatal("garbage accepted")
	}
	if err := Verify(w.valid(t), w.serverKey, ed25519.PublicKey(make([]byte, 31)), w.now); err == nil {
		t.Fatal("bad anchor length accepted")
	}
}

func TestBuildDetailsParse(t *testing.T) {
	raw := BuildDetails(5, 2, []byte{1, 2, 3}, time.Unix(1000, 0), time.Unix(2000, 0))
	m, err := pb.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := m.GetUint(1); v != 5 {
		t.Fatal("serial")
	}
	if v, _ := m.GetUint(2); v != 2 {
		t.Fatal("issuer serial")
	}
	if k, _ := m.GetBytes(3); len(k) != 3 {
		t.Fatal("key")
	}
	if v, _ := m.GetUint(4); v != 1000 {
		t.Fatal("notBefore")
	}
	if v, _ := m.GetUint(5); v != 2000 {
		t.Fatal("notAfter")
	}
}

func mustOtherRoot(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
