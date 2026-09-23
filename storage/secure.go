package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// SecureKV seals values of an underlying KV with AES-256-GCM under a master
// key. Keys (paths) are left in plaintext so List/prefix queries keep
// working; only the value bytes are encrypted, with the logical key bound as
// additional-authenticated-data so a sealed record cannot be replayed under
// a different key.
//
// Sealed format: "bseal1:" || base64(nonce[12] || ciphertext+tag).
//
// This addresses the "secrets at rest" audit item: session credentials and
// ratchet state (which embed private keys) are no longer stored as raw JSON.
type SecureKV struct {
	backend KV
	aead    cipher.AEAD
	owns    bool // close backend on Close when we created it via Wrap
}

// SealPrefix marks encrypted values.
const SealPrefix = "bseal1:"

var (
	// ErrSealedNotFound is returned when a value exists but is not sealed
	// (e.g. plaintext written before encryption was enabled).
	ErrSealedNotFound = errors.New("storage: value is not a sealed record")
	// ErrWrongKey surfaces decryption failures (tamper or wrong master).
	ErrWrongKey = errors.New("storage: decryption failed (wrong key or tampering)")
)

// NewSecureKV wraps backend with an AEAD built from a 32-byte master key.
func NewSecureKV(backend KV, masterKey []byte) (*SecureKV, error) {
	if backend == nil {
		return nil, errors.New("storage: nil backend")
	}
	if len(masterKey) != 32 {
		return nil, errors.New("storage: master key must be 32 bytes")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecureKV{backend: backend, aead: aead}, nil
}

// DeriveMaster turns a passphrase into a 32-byte master key with an
// iterated HMAC-SHA256 KDF (no scrypt/argon2 in the standard library). It
// is deliberately expensive; the salt is fixed per deployment via the
// optional context string.
func DeriveMaster(passphrase, salt []byte, iters int) []byte {
	if iters <= 0 {
		iters = 100_000
	}
	if len(salt) == 0 {
		salt = []byte("baturwhatsapi-seal-v1")
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(passphrase)
	t := mac.Sum(nil)
	for i := 0; i < iters; i++ {
		mac.Reset()
		mac.Write(t)
		t = mac.Sum(nil)
	}
	return t
}

var noncePool = sync.Pool{New: func() any { b := make([]byte, 12); return &b }}

func (s *SecureKV) seal(key string, value []byte) ([]byte, error) {
	nptr := noncePool.Get().(*[]byte)
	defer noncePool.Put(nptr)
	nonce := *nptr
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 12+len(value)+s.aead.Overhead())
	out = append(out, nonce...)
	out = s.aead.Seal(out, nonce[:12], value, []byte(key))
	return []byte(SealPrefix + base64.StdEncoding.EncodeToString(out)), nil
}

func (s *SecureKV) unseal(key string, sealed []byte) ([]byte, error) {
	raw := strings.TrimPrefix(string(sealed), SealPrefix)
	if raw == string(sealed) {
		return nil, ErrSealedNotFound
	}
	buf, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, ErrSealedNotFound
	}
	if len(buf) < 12 {
		return nil, ErrSealedNotFound
	}
	nonce, ct := buf[:12], buf[12:]
	plain, err := s.aead.Open(nil, nonce, ct, []byte(key))
	if err != nil {
		return nil, ErrWrongKey
	}
	return plain, nil
}

// Get implements KV (decrypts).
func (s *SecureKV) Get(ctx context.Context, key string) ([]byte, error) {
	sealed, err := s.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return s.unseal(key, sealed)
}

// Set implements KV (encrypts).
func (s *SecureKV) Set(ctx context.Context, key string, value []byte) error {
	sealed, err := s.seal(key, value)
	if err != nil {
		return err
	}
	return s.backend.Set(ctx, key, sealed)
}

// Delete implements KV (pass-through).
func (s *SecureKV) Delete(ctx context.Context, key string) error {
	return s.backend.Delete(ctx, key)
}

// List implements KV (pass-through; keys are not encrypted).
func (s *SecureKV) List(ctx context.Context, prefix string) ([]string, error) {
	return s.backend.List(ctx, prefix)
}

// Close implements KV.
func (s *SecureKV) Close() error { return s.backend.Close() }

// MasterKeyFromHex parses a 64-hex-char master key (from `batur keygen`).
func MasterKeyFromHex(hexStr string) ([]byte, error) {
	hexStr = strings.TrimSpace(hexStr)
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("storage: master key hex must be 64 chars, got %d", len(hexStr))
	}
	out := make([]byte, 32)
	if _, err := decodeHex(hexStr, out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeHex(s string, dst []byte) (int, error) {
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return 0, errors.New("storage: invalid hex")
		}
		dst[i/2] = hi<<4 | lo
	}
	return len(s) / 2, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

var _ KV = (*SecureKV)(nil)
