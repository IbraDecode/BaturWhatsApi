package e2e

import (
	"bytes"
	"testing"
)

func newFullPair(t *testing.T) (a, b *Ratchet) {
	t.Helper()
	info := []byte("batur-test")
	bobKeys, bundle, err := NewBobKeys()
	if err != nil {
		t.Fatal(err)
	}
	aliceID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a, err = AliceSession(bundle, aliceID, info)
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.Encrypt([]byte("open sesame"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err = BobSession(bobKeys, env, info)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestFullConversation(t *testing.T) {
	a, b := newFullPair(t)
	// A->B and B->A interleaved with ratchet crossings.
	type step struct {
		fromA bool
		text  string
	}
	steps := []step{
		{false, "bob reply 1"},
		{true, "alice 2"}, // crosses into bob's new chain
		{false, "bob 2"},
		{true, "alice 3"},
		{false, "bob 3"},
	}
	for i, st := range steps {
		if st.fromA {
			env, err := a.Encrypt([]byte(st.text))
			if err != nil {
				t.Fatal(err)
			}
			got, err := b.Decrypt(env)
			if err != nil {
				t.Fatalf("step %d bob decrypt: %v", i, err)
			}
			if string(got) != st.text {
				t.Fatalf("step %d: %q", i, got)
			}
		} else {
			env, err := b.Encrypt([]byte(st.text))
			if err != nil {
				t.Fatal(err)
			}
			got, err := a.Decrypt(env)
			if err != nil {
				t.Fatalf("step %d alice decrypt: %v", i, err)
			}
			if string(got) != st.text {
				t.Fatalf("step %d: %q", i, got)
			}
		}
	}
}

func TestOutOfOrder(t *testing.T) {
	a, b := newFullPair(t)
	envs := make([]Envelope, 5)
	var err error
	for i := range envs {
		envs[i], err = a.Encrypt([]byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	// deliver shuffled: 5th, 2nd, 1st, 4th, 3rd
	order := []int{4, 1, 0, 3, 2}
	for _, idx := range order {
		got, err := b.Decrypt(envs[idx])
		if err != nil {
			t.Fatalf("shuffle delivery idx %d: %v", idx, err)
		}
		if got[0] != byte('a'+idx) {
			t.Fatalf("idx %d got %q", idx, got)
		}
	}
}

func TestReplayRejected(t *testing.T) {
	a, b := newFullPair(t)
	env, _ := a.Encrypt([]byte("hello"))
	if _, err := b.Decrypt(env); err != nil {
		t.Fatal(err)
	}
	env2, _ := a.Encrypt([]byte("hello"))
	if _, err := b.Decrypt(env); err == nil && env.Counter == env2.Counter {
		// replaying the *first* message: counter behind chain -> reject
	}
	if _, err := b.Decrypt(env); err == nil {
		t.Fatal("replayed message accepted")
	}
}

func TestTamperRejected(t *testing.T) {
	a, b := newFullPair(t)
	env, _ := a.Encrypt([]byte("secret"))
	bad := env
	bad.Body[len(bad.Body)-1] ^= 0xFF
	if _, err := b.Decrypt(bad); err != ErrDecryptFailed {
		t.Fatalf("tampered body: %v", err)
	}
	bad2 := env
	bad2.RatchetPub[0] ^= 0x01
	if _, err := b.Decrypt(bad2); err == nil {
		t.Fatal("tampered ratchet pub accepted")
	}
}

func TestPersistenceResume(t *testing.T) {
	a, b := newFullPair(t)
	// exchange a few messages to advance state
	for i := 0; i < 3; i++ {
		env, _ := a.Encrypt([]byte{byte(i)})
		if _, err := b.Decrypt(env); err != nil {
			t.Fatal(err)
		}
		env2, _ := b.Encrypt([]byte{byte(i + 100)})
		if _, err := a.Decrypt(env2); err != nil {
			t.Fatal(err)
		}
	}
	sa, err := a.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	a2, err := RestoreRatchet(sa)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := RestoreRatchet(sb)
	if err != nil {
		t.Fatal(err)
	}
	// continue conversation across restored peers
	env, err := a2.Encrypt([]byte("after-restore"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := b2.Decrypt(env)
	if err != nil {
		t.Fatalf("decrypt after restore: %v", err)
	}
	if string(got) != "after-restore" {
		t.Fatalf("got %q", got)
	}
	env2, err := b2.Encrypt([]byte("reply-after-restore"))
	if err != nil {
		t.Fatal(err)
	}
	got2, err := a2.Decrypt(env2)
	if err != nil {
		t.Fatalf("reply decrypt after restore: %v", err)
	}
	if string(got2) != "reply-after-restore" {
		t.Fatalf("got2 %q", got2)
	}
}

func TestSkipLimitGuard(t *testing.T) {
	a, b := newFullPair(t)
	// Alice sends 5 msgs; Bob delivers the 5th first (forces 4 skips —
	// fine), then ensure buffer accounting works and old messages fail.
	envs := make([]Envelope, 5)
	var err error
	for i := range envs {
		envs[i], err = a.Encrypt([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Decrypt(envs[4]); err != nil {
		t.Fatal(err)
	}
	// Now earlier messages are within skip budget: they should decrypt.
	for i := 0; i < 4; i++ {
		if _, err := b.Decrypt(envs[i]); err != nil {
			t.Fatalf("skipped msg %d rejected: %v", i, err)
		}
	}
}

func TestBundleTamper(t *testing.T) {
	_, bundle, err := NewBobKeys()
	if err != nil {
		t.Fatal(err)
	}
	bundle.SignedPreKeySig[3] ^= 0x40
	aliceID, _ := NewIdentity()
	if _, err := AliceSession(bundle, aliceID, []byte("x")); err == nil || !bytes.Contains([]byte(err.Error()), []byte("prekey")) {
		t.Fatalf("expected spk signature rejection, got %v", err)
	}
}

func TestEnvelopeWireRoundTrip(t *testing.T) {
	a, _ := newFullPair(t)
	env, err := a.Encrypt([]byte("wire"))
	if err != nil {
		t.Fatal(err)
	}
	raw := env.Serialize()
	back, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Type != env.Type || !bytes.Equal(back.Body, env.Body) ||
		!bytes.Equal(back.RatchetPub, env.RatchetPub) || back.Counter != env.Counter {
		t.Fatal("envelope wire roundtrip lost data")
	}
}
