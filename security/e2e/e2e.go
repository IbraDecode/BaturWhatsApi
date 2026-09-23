// Package e2e implements BaturWhatsApi's end-to-end messaging cryptography:
// X3DH key agreement plus a Double Ratchet session, built exclusively from
// Go standard-library primitives (see ADR-0006).
//
// Cipher suite (engine-to-engine):
//   - identity & ratchet DH keys: X25519 (crypto/ecdh)
//   - identity certification / signed-prekey signatures: Ed25519
//   - KDFs: HKDF-SHA256 (security/hkdf) and HMAC-SHA256 chains
//   - message bodies: AES-256-GCM (per-message keys via HKDF expansion)
//   - headers: AES-256-CBC zero-IV + PKCS#7 (Signal-compatible)
//
// Wire: Envelope (pb serialization) — Batur's own; mapping to WhatsApp's
// SignalMessage proto is scheduled in T-102.
package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ibradecode/baturwhatsapi/security/hkdf"
)

var randRead = rand.Read

// ProtocolInfoV1 is the HKDF info binding for all engine-to-engine X3DH
// derivations (protocol revision marker).
var ProtocolInfoV1 = []byte("baturwhatsapi-e2e-v1")

// Errors.
var (
	ErrBadKey        = errors.New("e2e: invalid key material")
	ErrDecryptFailed = errors.New("e2e: decryption failed")
	ErrNoSession     = errors.New("e2e: no session established")
	ErrBundleInvalid = errors.New("e2e: prekey bundle failed verification")
)

// ---------------------------------------------------------------------------
// keys

// KeyPair is an X25519 key pair.
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// NewKeyPair generates a random X25519 key pair.
func NewKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{priv: priv}, nil
}

// KeyPairFromSeed restores a key pair from a 32-byte seed.
func KeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != 32 {
		return nil, ErrBadKey
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, ErrBadKey
	}
	return &KeyPair{priv: priv}, nil
}

// Public returns the 32-byte X25519 public key.
func (k *KeyPair) Public() []byte { return k.priv.PublicKey().Bytes() }

// Seed returns the private seed for persistence.
func (k *KeyPair) Seed() []byte { return k.priv.Bytes() }

func dh(priv *KeyPair, peerRaw []byte) ([]byte, error) {
	peer, err := ecdh.X25519().NewPublicKey(peerRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	return priv.priv.ECDH(peer)
}

// Identity bundles a long-lived X25519 DH identity, an Ed25519 signing key
// (certifies the DH identity and signed prekeys) and a registration id.
type Identity struct {
	DH       *KeyPair
	SignPub  ed25519.PublicKey
	signPriv ed25519.PrivateKey
	RegID    uint32
}

// NewIdentity creates fresh identity material.
func NewIdentity() (*Identity, error) {
	dhKP, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &Identity{
		DH: dhKP, SignPub: pub, signPriv: priv,
		RegID: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
	}, nil
}

// RestoreIdentity reloads from seeds.
func RestoreIdentity(dhSeed, sigSeed []byte, regID uint32) (*Identity, error) {
	dhKP, err := KeyPairFromSeed(dhSeed)
	if err != nil {
		return nil, err
	}
	if len(sigSeed) != ed25519.SeedSize {
		return nil, ErrBadKey
	}
	priv := ed25519.NewKeyFromSeed(sigSeed)
	return &Identity{DH: dhKP, SignPub: priv.Public().(ed25519.PublicKey), signPriv: priv, RegID: regID}, nil
}

// Sign returns the ed25519 signature over msg.
func (id *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(id.signPriv, msg)
}

// SignPub returns the identity signing public key.
func (id *Identity) SignPubKey() ed25519.PublicKey { return id.SignPub }

// seeds for persistence
func (id *Identity) signSeed() []byte { return id.signPriv.Seed() }

// ---------------------------------------------------------------------------
// X3DH prekey bundle

// PreKeyBundle is a peer's published X3DH material.
type PreKeyBundle struct {
	IdentityPub     []byte // X25519
	IdentitySigPub  []byte // Ed25519
	IdentityCert    []byte // Ed25519 sig over identity DH pub
	RegID           uint32
	SignedPreKeyPub []byte
	SignedPreKeyID  uint32
	SignedPreKeySig []byte // Ed25519 sig over identity-cert || spk-pub || id
	OneTimePreKeys  map[uint32][]byte
}

// spkCertMessage is the exact signed statement binding a signed prekey to
// an identity: domain tag + identity cert + spk material + id.
func spkCertMessage(identityCert, spkPub []byte, spkID uint32) []byte {
	out := append([]byte("batur-e2e-spk-v1\x00"), identityCert...)
	out = append(out, spkPub...)
	out = append(out, byte(spkID>>24), byte(spkID>>16), byte(spkID>>8), byte(spkID))
	return out
}

func idCertMessage(dhPub []byte) []byte {
	return append([]byte("batur-e2e-id-v1\x00"), dhPub...)
}

// BuildBundle assembles and signs a bundle from live key material.
func BuildBundle(id *Identity, spk *KeyPair, spkID uint32, oneTime map[uint32][]byte) *PreKeyBundle {
	idCert := id.Sign(idCertMessage(id.DH.Public()))
	sig := id.Sign(spkCertMessage(idCert, spk.Public(), spkID))
	if oneTime == nil {
		oneTime = map[uint32][]byte{}
	}
	return &PreKeyBundle{
		IdentityPub:     id.DH.Public(),
		IdentitySigPub:  id.SignPub,
		IdentityCert:    idCert,
		RegID:           id.RegID,
		SignedPreKeyPub: spk.Public(),
		SignedPreKeyID:  spkID,
		SignedPreKeySig: sig,
		OneTimePreKeys:  oneTime,
	}
}

// VerifyBundle checks both Ed25519 signatures in the bundle.
func VerifyBundle(b *PreKeyBundle) error {
	if len(b.IdentityPub) != 32 || len(b.IdentitySigPub) != ed25519.PublicKeySize ||
		len(b.SignedPreKeyPub) != 32 {
		return ErrBundleInvalid
	}
	if !ed25519.Verify(b.IdentitySigPub, idCertMessage(b.IdentityPub), b.IdentityCert) {
		return fmt.Errorf("%w: identity certificate", ErrBundleInvalid)
	}
	want := spkCertMessage(b.IdentityCert, b.SignedPreKeyPub, b.SignedPreKeyID)
	if !ed25519.Verify(b.IdentitySigPub, want, b.SignedPreKeySig) {
		return fmt.Errorf("%w: signed prekey", ErrBundleInvalid)
	}
	return nil
}

// ---------------------------------------------------------------------------
// X3DH derivation

var x3dhZero = make([]byte, 32)

// X3DHInitiator derives (rootKey, chainKey). ephemeral must be the
// initiator's first ratchet key pair (Signal convention: reuse).
func X3DHInitiator(identity, ephemeral *KeyPair, bundle *PreKeyBundle, info []byte) (rootKey, chainKey []byte, err error) {
	d1, err := dh(identity, bundle.IdentityPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: DH1: %w", err)
	}
	d2, err := dh(ephemeral, bundle.SignedPreKeyPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: DH2: %w", err)
	}
	d3, err := dh(identity, bundle.SignedPreKeyPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: DH3: %w", err)
	}
	ikm := make([]byte, 0, 160)
	ikm = append(ikm, d1...)
	ikm = append(ikm, d2...)
	ikm = append(ikm, d3...)
	var opkPub []byte
	for _, k := range bundle.OneTimePreKeys {
		opkPub = k // first available one-time prekey
		break
	}
	if opkPub != nil {
		d4, err := dh(ephemeral, opkPub)
		if err != nil {
			return nil, nil, fmt.Errorf("x3dh: DH4: %w", err)
		}
		ikm = append(ikm, d4...)
	} else {
		ikm = append(ikm, x3dhZero...) // DH4-absent marker
	}
	rootKey, chainKey, err = x3dhDerive(ikm, info)
	return rootKey, chainKey, nil
}

// X3DHRecipient mirrors the initiator using responder private keys.
func X3DHRecipient(identity, spkPriv *KeyPair, senderIdentityPub, senderEphemeralPub []byte, oneTimePriv *KeyPair, info []byte) (rootKey, chainKey []byte, err error) {
	d1, err := dh(identity, senderIdentityPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: DH1: %w", err)
	}
	d2, err := dh(spkPriv, senderEphemeralPub)
	if err != nil {
		return nil, nil, err
	}
	d3, err := dh(spkPriv, senderIdentityPub)
	if err != nil {
		return nil, nil, err
	}
	ikm := make([]byte, 0, 160)
	ikm = append(ikm, d1...)
	ikm = append(ikm, d2...)
	ikm = append(ikm, d3...)
	if oneTimePriv != nil {
		d4, err := dh(oneTimePriv, senderEphemeralPub)
		if err != nil {
			return nil, nil, err
		}
		ikm = append(ikm, d4...)
	} else {
		ikm = append(ikm, x3dhZero...)
	}
	return x3dhDerive(ikm, info)
}

// x3dhDerive splits 96 bytes into root||chain||marker.
func x3dhDerive(ikm, info []byte) (rootKey, chainKey []byte, err error) {
	full, err := hkdf.Derive(ikm, x3dhZero, info, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: derive: %w", err)
	}
	return full[:32], full[32:64], nil
}

// ---------------------------------------------------------------------------
// KDFs

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func kdfRoot(rootKey, dhOut []byte) (newRoot, chainKey []byte) {
	newRoot = hmacSHA256(rootKey, append([]byte{0x80}, dhOut...))
	chainKey = hmacSHA256(rootKey, append([]byte{0x07}, dhOut...))
	return
}

func kdfChain(chainKey []byte) (msgKey, next []byte) {
	msgKey = hmacSHA256(chainKey, []byte{0x01})
	next = hmacSHA256(chainKey, []byte{0x02})
	return
}

func expandMessageKey(msgKey []byte) (aesKey, iv []byte) {
	out, err := hkdf.Derive(msgKey, []byte("batur-e2e-keys"), []byte("msg"), 44)
	if err != nil {
		panic("e2e: hkdf expand: " + err.Error()) // fixed length is valid
	}
	return out[:32], out[32:44]
}

// ---------------------------------------------------------------------------
// primitives: CBC header, GCM body

func encryptHeader(sharedKey, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	padded := pkcs7(plaintext, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, padded)
	return out, nil
}

func decryptHeader(sharedKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, ciphertext)
	plain, err := unpkcs7(out)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plain, nil
}

func pkcs7(data []byte, bs int) []byte {
	pad := bs - len(data)%bs
	out := make([]byte, 0, len(data)+pad)
	out = append(out, data...)
	for i := 0; i < pad; i++ {
		out = append(out, byte(pad))
	}
	return out
}

func unpkcs7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(data) {
		return nil, errors.New("bad padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("bad padding")
		}
	}
	return data[:len(data)-pad], nil
}

func aesGCMEncrypt(key, iv, plaintext, ad []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("e2e: aes: " + err.Error())
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		panic("e2e: gcm: " + err.Error())
	}
	return gcm.Seal(nil, iv, plaintext, ad)
}

func aesGCMDecrypt(key, iv, ciphertext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, ErrDecryptFailed
	}
	pt, err := gcm.Open(nil, iv, ciphertext, ad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}
