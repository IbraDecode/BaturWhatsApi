// Package hkdf implements HKDF (RFC 5869) over SHA-256 using only the Go
// standard library. The engine keeps this dependency-free so cryptographic
// state derivation never pulls third-party code into the core.
package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// Hash is the hash function used by all Batur key derivation (SHA-256).
const HashSize = sha256.Size

// ErrOutputTooLong exceeds RFC 5869 bounds (255 * HashSize).
var ErrOutputTooLong = errors.New("hkdf: requested output too long")

// Extract returns PRK = HMAC-SHA256(salt, secret). A nil salt is treated as
// a zero-filled salt per the RFC.
func Extract(secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, HashSize)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(secret)
	return m.Sum(nil)
}

// Expand returns the first length bytes of OKM = HKDF-Expand-SHA256(PRK,
// info, length).
func Expand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*HashSize {
		return nil, ErrOutputTooLong
	}
	var out, previous []byte
	var counter byte = 1
	m := hmac.New(sha256.New, prk)
	for len(out) < length {
		m.Reset()
		m.Write(previous)
		m.Write(info)
		m.Write([]byte{counter})
		previous = m.Sum(nil)
		out = append(out, previous...)
		counter++
	}
	return out[:length], nil
}

// Derive runs Extract then Expand.
func Derive(secret, salt, info []byte, length int) ([]byte, error) {
	return Expand(Extract(secret, salt), info, length)
}

// Keys derives 2*n bytes and splits them (used by the Noise key chain for
// paired read/write keys).
func Keys(secret, salt, info []byte, n int) (first, second []byte, err error) {
	out, err := Derive(secret, salt, info, 2*n)
	if err != nil {
		return nil, nil, err
	}
	return out[:n], out[n : 2*n], nil
}
