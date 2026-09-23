// Package noise implements the Noise_XX_25519_AESGCM_SHA256 handshake and
// transport ciphers as used by the WhatsApp Web control socket, with
// BaturWhatsApi's own API surface and architecture.
//
// Only established primitives from the Go standard library are used
// (crypto/ecdh X25519, AES-256-GCM, HMAC-SHA256, HKDF). Nothing here is a
// custom cipher.
package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ibradecode/baturwhatsapi/security/hkdf"
)

// StartPattern is the exact 32-byte prologue used by WhatsApp web sockets.
const StartPattern = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"

// Errors.
var (
	ErrHandshakeState = errors.New("noise: invalid handshake state")
	ErrDecryptFailed  = errors.New("noise: decryption failed")
)

func sha256sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("noise: aes init failed: " + err.Error())
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		panic("noise: gcm init failed: " + err.Error())
	}
	return a
}

func iv(counter uint32) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint32(out[8:], counter)
	return out
}

// Cipher is a transport-direction AEAD stream (AES-256-GCM, big-endian
// counter IV starting at zero).
type Cipher struct {
	aead    cipher.AEAD
	counter uint32
}

// NewCipher wraps a 32-byte key.
func NewCipher(key []byte) *Cipher { return &Cipher{aead: gcm(key)} }

// Seal encrypts with the next counter value.
func (c *Cipher) Seal(dst, plaintext []byte) []byte {
	out := c.aead.Seal(dst, iv(c.counter), plaintext, nil)
	c.counter++
	return out
}

// Open decrypts with the next counter value.
func (c *Cipher) Open(dst, ciphertext []byte) ([]byte, error) {
	out, err := c.aead.Open(dst, iv(c.counter), ciphertext, nil)
	c.counter++
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return out, nil
}

// Counter exposes the nonce counter for persistence/health checks.
func (c *Cipher) Counter() uint32 { return c.counter }

// Handshake implements the symmetric Noise state (h, ck, AES-GCM cipher)
// shared by initiator and responder.
type Handshake struct {
	h       []byte
	ck      []byte
	k       cipher.AEAD // current transport cipher for handshake messages
	counter uint32
}

// NewHandshake initializes the state from the protocol name and optional
// header (HTTP headers of the underlying transport, mixed as the first
// authenticated data).
func NewHandshake(pattern string, header []byte) *Handshake {
	var h []byte
	if len(pattern) == 32 {
		h = []byte(pattern)
	} else {
		h = sha256sum([]byte(pattern))
	}
	nh := &Handshake{h: h, ck: h}
	nh.k = gcm(nh.ck)
	nh.Authenticate(header)
	return nh
}

// Authenticate mixes data into the handshake hash.
func (nh *Handshake) Authenticate(data []byte) {
	nh.h = sha256sum(append(append([]byte{}, nh.h...), data...))
}

// encryptWithAD seals under the current key, authenticating the ciphertext
// into h.
func (nh *Handshake) encrypt(plaintext []byte) []byte {
	ct := nh.k.Seal(nil, iv(nh.counter), plaintext, nh.h)
	nh.counter++
	nh.Authenticate(ct)
	return ct
}

func (nh *Handshake) decrypt(ciphertext []byte) ([]byte, error) {
	pt, err := nh.k.Open(nil, iv(nh.counter), ciphertext, nh.h)
	nh.counter++
	if err != nil {
		return nil, ErrDecryptFailed
	}
	nh.Authenticate(ciphertext)
	return pt, nil
}

// MixKey performs Noise MixKey: re-derive ck and the transport key with the
// given shared secret as additional input.
func (nh *Handshake) MixKey(secret []byte) error {
	nh.counter = 0
	write, read, err := nh.extractExpand(secret)
	if err != nil {
		return err
	}
	nh.ck = write
	nh.k = gcm(read)
	return nil
}

func (nh *Handshake) extractExpand(secret []byte) ([]byte, []byte, error) {
	return hkdf.Keys(secret, nh.ck, nil, 32)
}

// MixHash folds arbitrary bytes into h without encryption.
func (nh *Handshake) MixHash(data []byte) { nh.Authenticate(data) }

// HandshakeKeys are the final send/receive transport keys.
type HandshakeKeys struct {
	Send, Recv []byte
}

// SendKeys derives the transport direction keys. initiator reports whether
// this party started the handshake; keys are returned already oriented for
// that party.
func (nh *Handshake) SendKeys(initiator bool) (*HandshakeKeys, error) {
	send, recv, err := nh.extractExpand(nil)
	if err != nil {
		return nil, err
	}
	if !initiator {
		send, recv = recv, send
	}
	return &HandshakeKeys{Send: send, Recv: recv}, nil
}

// Hash returns the current handshake hash (channel binding value).
func (nh *Handshake) Hash() []byte { return append([]byte{}, nh.h...) }

// KeyPair wraps an X25519 key pair.
type KeyPair struct {
	Priv *ecdh.PrivateKey
}

// NewKeyPair generates a fresh X25519 key pair.
func NewKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("noise: generate key: %w", err)
	}
	return &KeyPair{Priv: priv}, nil
}

// KeyPairFromSeed restores a key pair from a 32-byte private seed.
func KeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != 32 {
		return nil, errors.New("noise: seed must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("noise: restore key: %w", err)
	}
	return &KeyPair{Priv: priv}, nil
}

// Public returns the 32-byte public key.
func (kp *KeyPair) Public() []byte { return kp.Priv.PublicKey().Bytes() }

// Seed returns the private key seed for persistence.
func (kp *KeyPair) Seed() []byte { return kp.Priv.Bytes() }

// XX implements the WhatsApp-flavored Noise XX pattern between a client
// (initiator) and server (responder). WhatsApp semantics:
//
//	-> e                 (ClientHello with ephemeral, plaintext)
//	<- e, es, s          (ServerHello)
//	<- ... payload under static mix
//	-> s, se, payload    (ClientFinish)
//
// The engine uses this both to talk to the real servers and to run its
// protocol-level test servers.
type XX struct {
	nh           *Handshake
	initiator    bool
	static       *KeyPair // own static key
	remoteStatic []byte
	remoteEph    []byte
	eph          *KeyPair
	done         bool
}

// NewXXClient starts an initiator handshake. static is the client noise key
// pair (may be freshly generated for ephemeral-only probing).
func NewXXClient(static *KeyPair, header []byte) (*XX, error) {
	return &XX{nh: NewHandshake(StartPattern, header), initiator: true, static: static}, nil
}

// NewXXServer starts a responder handshake.
func NewXXServer(static *KeyPair, header []byte) (*XX, error) {
	return &XX{nh: NewHandshake(StartPattern, header), initiator: false, static: static}, nil
}

// ClientHello1 produces the first message payload (already AEAD-wrapped if
// you need the ciphertext form; here it returns the ephemeral public key and
// mixes it into the hash like WhatsApp does out-of-band in protobuf).
func (xx *XX) ClientHello1() (ephPub []byte, err error) {
	if !xx.initiator {
		return nil, ErrHandshakeState
	}
	xx.eph, err = NewKeyPair()
	if err != nil {
		return nil, err
	}
	xx.nh.Authenticate(xx.eph.Public())
	return xx.eph.Public(), nil
}

// WriteHello wraps arbitrary client-hello payload bytes under the current
// cipher.
func (xx *XX) WriteHello(payload []byte) []byte {
	return xx.nh.encrypt(payload)
}

// ReadHello decrypts a client-hello payload.
func (xx *XX) ReadHello(payload []byte) ([]byte, error) {
	return xx.nh.decrypt(payload)
}

// ServerHello1: responder consumes client ephemeral (ephPub) and returns
// its own ephemeral plus an encrypted static+payload blob:
//
//	s:   EncryptWithHash(staticPub)
//	payload: encrypted application payload
func (xx *XX) ServerHello1(ephPub, payload []byte) (serverEph []byte, staticCT []byte, payloadCT []byte, err error) {
	if xx.initiator {
		return nil, nil, nil, ErrHandshakeState
	}
	xx.remoteEph = ephPub
	xx.nh.Authenticate(ephPub)
	xx.eph, err = NewKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}
	xx.nh.Authenticate(xx.eph.Public())
	if err = xx.mix(xx.eph.Priv, ephPub); err != nil {
		return nil, nil, nil, err
	}
	staticCT = xx.nh.encrypt(xx.static.Public())
	// es' (responder -> initiator direction)
	if err = xx.mix(xx.static.Priv, ephPub); err != nil {
		return nil, nil, nil, err
	}
	payloadCT = xx.nh.encrypt(payload)
	return xx.eph.Public(), staticCT, payloadCT, nil
}

// ClientFinish: initiator processes the server output and produces its own
// static ciphertext + payload ciphertext.
func (xx *XX) ClientFinish(serverEph, staticCT, payloadCT []byte, payload []byte) (clientStaticCT, clientPayloadCT []byte, err error) {
	if !xx.initiator {
		return nil, nil, ErrHandshakeState
	}
	xx.remoteEph = serverEph
	xx.nh.Authenticate(serverEph)
	if err = xx.mix(xx.eph.Priv, serverEph); err != nil {
		return nil, nil, err
	}
	remoteStatic, err := xx.nh.decrypt(staticCT)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: server static: %w", err)
	}
	xx.remoteStatic = remoteStatic
	if err = xx.mix(xx.eph.Priv, remoteStatic); err != nil {
		return nil, nil, err
	}
	if _, err = xx.nh.decrypt(payloadCT); err != nil {
		return nil, nil, fmt.Errorf("noise: server payload: %w", err)
	}
	// -> s (encrypted under current key), then se
	clientStaticCT = xx.nh.encrypt(xx.static.Public())
	if err = xx.mix(xx.static.Priv, serverEph); err != nil {
		return nil, nil, err
	}
	clientPayloadCT = xx.nh.encrypt(payload)
	xx.done = true
	return clientStaticCT, clientPayloadCT, nil
}

// AcceptFinish: responder processes client static + payload.
func (xx *XX) AcceptFinish(clientStaticCT, clientPayloadCT []byte) (peerStatic []byte, payload []byte, err error) {
	if xx.initiator {
		return nil, nil, ErrHandshakeState
	}
	remote, err := xx.nh.decrypt(clientStaticCT)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: client static: %w", err)
	}
	xx.remoteStatic = remote
	if err = xx.mix(xx.eph.Priv, remote); err != nil {
		return nil, nil, err
	}
	payload, err = xx.nh.decrypt(clientPayloadCT)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: client payload: %w", err)
	}
	xx.done = true
	return remote, payload, nil
}

// ServerHelloPayload: initiator-only helper to decrypt a payload attached
// before the finish round (used when the payload arrives in ServerHello).
func (xx *XX) RemoteStatic() []byte { return xx.remoteStatic }

// Done reports handshake completion.
func (xx *XX) Done() bool { return xx.done }

func (xx *XX) mix(priv *ecdh.PrivateKey, peerPub []byte) error {
	peer, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return fmt.Errorf("noise: bad peer key: %w", err)
	}
	secret, err := priv.ECDH(peer)
	if err != nil {
		return fmt.Errorf("noise: ecdh failed: %w", err)
	}
	return xx.nh.MixKey(secret)
}

// SendCipher builds the transport cipher pair. Both parties call after Done.
func (xx *XX) SendCipher() (*Cipher, *Cipher, error) {
	if !xx.done {
		return nil, nil, ErrHandshakeState
	}
	keys, err := xx.nh.SendKeys(xx.initiator)
	if err != nil {
		return nil, nil, err
	}
	return NewCipher(keys.Send), NewCipher(keys.Recv), nil
}
