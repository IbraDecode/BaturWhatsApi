package storage

import (
	"bytes"
	"context"
	"testing"
)

func TestSecureKVBasic(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	key[0] = 42
	mem := NewMemory()
	skv, err := NewSecureKV(mem, key)
	if err != nil {
		t.Fatal(err)
	}
	defer skv.Close()

	secret := []byte(`{"noise_key":"super-secret-seed"}`)
	if err := skv.Set(ctx, "session/a/credentials", secret); err != nil {
		t.Fatal(err)
	}
	// Backend must not contain plaintext.
	raw, err := mem.Get(ctx, "session/a/credentials")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("super-secret")) {
		t.Fatal("plaintext leaked to backend")
	}
	if !bytes.HasPrefix(raw, []byte(SealPrefix)) {
		t.Fatal("value not sealed")
	}
	// Round-trip.
	got, err := skv.Get(ctx, "session/a/credentials")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	// Nonce randomness: two seals of same value differ.
	other := make([]byte, len(secret))
	copy(other, secret)
	if err := skv.Set(ctx, "session/b/creds", other); err != nil {
		t.Fatal(err)
	}
	r1, _ := mem.Get(ctx, "session/a/credentials")
	r2, _ := mem.Get(ctx, "session/b/creds")
	if bytes.Equal(r1, r2) {
		t.Fatal("nonce reuse: identical ciphertext for different keys")
	}
}

func TestSecureKVBindsKeyPath(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{7}, 32)
	mem := NewMemory()
	skv, _ := NewSecureKV(mem, key)
	_ = skv.Set(ctx, "session/a/x", []byte("payload-A"))
	_ = skv.Set(ctx, "session/b/x", []byte("payload-B"))
	// Copy A's sealed blob to B's slot: must fail AD check (key binding).
	raw, _ := mem.Get(ctx, "session/a/x")
	if err := mem.Set(ctx, "session/b/x", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := skv.Get(ctx, "session/b/x"); err != ErrWrongKey {
		t.Fatalf("cross-key replay accepted: %v", err)
	}
}

func TestSecureKVTamperAndWrongKey(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{1}, 32)
	mem := NewMemory()
	skv, _ := NewSecureKV(mem, key)
	_ = skv.Set(ctx, "k", []byte("data"))
	raw, _ := mem.Get(ctx, "k")
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-3] ^= 0xFF // flip inside base64 alphabet region
	mem.Set(ctx, "k", tampered)
	if _, err := skv.Get(ctx, "k"); err != ErrWrongKey && err != ErrSealedNotFound {
		t.Fatalf("tamper accepted: %v", err)
	}
	// Wrong master key (fresh clean record).
	_ = skv.Set(ctx, "k2", []byte("data2"))
	skv2, _ := NewSecureKV(mem, bytes.Repeat([]byte{2}, 32))
	if _, err := skv2.Get(ctx, "k2"); err != ErrWrongKey {
		t.Fatalf("wrong key accepted: %v", err)
	}
	// Unsealed (plaintext legacy) value detection.
	mem.Set(ctx, "legacy", []byte(`{"plain":true}`))
	if _, err := skv.Get(ctx, "legacy"); err != ErrSealedNotFound {
		t.Fatalf("expected ErrSealedNotFound, got %v", err)
	}
}

func TestDeriveMaster(t *testing.T) {
	k1 := DeriveMaster([]byte("passphrase"), nil, 1000)
	k2 := DeriveMaster([]byte("passphrase"), nil, 1000)
	k3 := DeriveMaster([]byte("Passphrase"), nil, 1000)
	if len(k1) != 32 {
		t.Fatal("length")
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("KDF not deterministic")
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("KDF insensitive to input")
	}
}

func TestMasterKeyFromHex(t *testing.T) {
	k, err := MasterKeyFromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil || len(k) != 32 || k[1] != 0x11 {
		t.Fatalf("hex parse: %v %v", k, err)
	}
	if _, err := MasterKeyFromHex("nothex"); err == nil {
		t.Fatal("bad hex accepted")
	}
	if _, err := MasterKeyFromHex("zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("invalid hex chars accepted")
	}
}

func TestSecureFileStoreEndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	skv, err := NewSecureKV(fs, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := skv.Set(ctx, "session/s/credentials", []byte("PRIVATE")); err != nil {
		t.Fatal(err)
	}
	// Reopen: still sealed and decryptable.
	fs2, _ := NewFileStore(dir)
	skv2, _ := NewSecureKV(fs2, bytes.Repeat([]byte{9}, 32))
	got, err := skv2.Get(ctx, "session/s/credentials")
	if err != nil || string(got) != "PRIVATE" {
		t.Fatalf("durable sealed read: %q %v", got, err)
	}
	keys, _ := skv2.List(ctx, "session/s/")
	if len(keys) != 1 {
		t.Fatalf("list = %v", keys)
	}
}
