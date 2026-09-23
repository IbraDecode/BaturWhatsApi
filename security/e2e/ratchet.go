package e2e

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/ibradecode/baturwhatsapi/protocol/pb"
)

// Envelope types.
const (
	EnvInit    = 1 // X3DH first message (initiator only)
	EnvRatchet = 2 // regular Double Ratchet message
)

// envelope wire fields (pb).
const (
	envFieldVersion = 1
	envFieldType    = 2
	envFieldRatchet = 3
	envFieldPrev    = 4
	envFieldCounter = 5
	envFieldHeader  = 6
	envFieldBody    = 7
	envFieldIDPub   = 8
	envFieldRegID   = 9
	envFieldOpkID   = 10
	envFieldSigPub  = 11
	envFieldIDCert  = 12
)

// initTag authenticates root-key possession inside the init header.
var initTag = []byte("batur-e2e-init-v1")

// Envelope is a transmitted encrypted message.
type Envelope struct {
	Version       byte
	Type          byte
	RatchetPub    []byte
	PrevCount     uint32
	Counter       uint32
	HeaderEncrypt []byte
	Body          []byte
	// Init-only plaintext handshake fields:
	IdentityPub    []byte
	IdentitySigPub []byte
	IdentityCert   []byte
	RegID          uint32
	OpkID          uint32
}

// Serialize encodes the envelope.
func (e Envelope) Serialize() []byte {
	b := pb.NewBuilder().
		Uint(envFieldVersion, uint64(e.Version)).
		Uint(envFieldType, uint64(e.Type)).
		Bytes(envFieldRatchet, e.RatchetPub).
		Uint(envFieldPrev, uint64(e.PrevCount)).
		Uint(envFieldCounter, uint64(e.Counter)).
		Bytes(envFieldHeader, e.HeaderEncrypt).
		Bytes(envFieldBody, e.Body)
	if e.Type == EnvInit {
		b = b.Bytes(envFieldIDPub, e.IdentityPub).
			Bytes(envFieldSigPub, e.IdentitySigPub).
			Bytes(envFieldIDCert, e.IdentityCert).
			Uint(envFieldRegID, uint64(e.RegID)).
			Uint(envFieldOpkID, uint64(e.OpkID))
	}
	return b.Build()
}

// ParseEnvelope decodes a wire envelope.
func ParseEnvelope(data []byte) (Envelope, error) {
	m, err := pb.Parse(data)
	if err != nil {
		return Envelope{}, err
	}
	var e Envelope
	if v, ok := m.GetUint(envFieldVersion); ok {
		e.Version = byte(v)
	}
	if v, ok := m.GetUint(envFieldType); ok {
		e.Type = byte(v)
	}
	e.RatchetPub, _ = m.GetBytes(envFieldRatchet)
	if v, ok := m.GetUint(envFieldPrev); ok {
		e.PrevCount = uint32(v)
	}
	if v, ok := m.GetUint(envFieldCounter); ok {
		e.Counter = uint32(v)
	}
	e.HeaderEncrypt, _ = m.GetBytes(envFieldHeader)
	e.Body, _ = m.GetBytes(envFieldBody)
	e.IdentityPub, _ = m.GetBytes(envFieldIDPub)
	e.IdentitySigPub, _ = m.GetBytes(envFieldSigPub)
	e.IdentityCert, _ = m.GetBytes(envFieldIDCert)
	if v, ok := m.GetUint(envFieldRegID); ok {
		e.RegID = uint32(v)
	}
	if v, ok := m.GetUint(envFieldOpkID); ok {
		e.OpkID = uint32(v)
	}
	if e.Version != 1 || (e.Type != EnvInit && e.Type != EnvRatchet) {
		return Envelope{}, fmt.Errorf("e2e: bad envelope v=%d t=%d", e.Version, e.Type)
	}
	if len(e.RatchetPub) != 32 {
		return Envelope{}, ErrBadKey
	}
	return e, nil
}

// chainIndex keys skipped message keys.
type chainIndex struct {
	Ratchet [32]byte
	PN      uint32
	N       uint32
}

// MaxSkippedMessageKeys bounds out-of-order buffering (DoS guard).
const MaxSkippedMessageKeys = 1000

// Ratchet is a Double Ratchet session. Concurrent-safe via one mutex.
//
// Root-chain protocol (both peers see identical DH order):
//
//	init:  root R0; initiator chain0 = X3DH chain (pub E)
//	on receiving new remote pub P: [skip old receive chain] then
//	    (rootR, recvChain) = KDF(root, DH(mySendPriv, P))
//	    and my old sending chain is retired; the next Encrypt does
//	    (rootS, sendChain) = KDF(root, DH(newPriv, myRecvPub)).
type Ratchet struct {
	mu sync.Mutex

	rootKey          []byte
	sendingChain     []byte // nil until ensureSendingChain
	recvChain        []byte
	sendingDH        *KeyPair
	recvPub          [32]byte
	haveRecvPub      bool
	initSent         bool
	isInitiator      bool
	sendingCounter   uint32
	receivingCounter uint32
	previousCounter  uint32 // count of messages on the *retired* send chain
	retiredSendCount uint32

	skipped map[chainIndex][]byte

	// self identity for init envelopes
	selfDH  []byte
	selfSig []byte
	selfID  uint32
	signer  func([]byte) []byte

	peerIdentityPub []byte
	peerSigPub      []byte
	peerRegID       uint32
	opkID           uint32
	spkID           uint32
	initInfo        []byte
	maxSkip         int
}

// AliceSession initiates a session toward bundle (verified). The
// initiator's first sending pair doubles as the X3DH ephemeral key.
func AliceSession(bundle *PreKeyBundle, identity *Identity, info []byte) (*Ratchet, error) {
	if err := VerifyBundle(bundle); err != nil {
		return nil, err
	}
	eph, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	root, chain, err := X3DHInitiator(identity.DH, eph, bundle, info)
	if err != nil {
		return nil, err
	}
	r := &Ratchet{
		rootKey:         root,
		sendingChain:    chain,
		sendingDH:       eph,
		initInfo:        info,
		maxSkip:         MaxSkippedMessageKeys,
		isInitiator:     true,
		peerIdentityPub: bundle.IdentityPub,
		peerSigPub:      bundle.IdentitySigPub,
		peerRegID:       bundle.RegID,
		spkID:           bundle.SignedPreKeyID,
		selfDH:          identity.DH.Public(),
		selfSig:         identity.SignPub,
		selfID:          identity.RegID,
		signer:          identity.Sign,
		skipped:         map[chainIndex][]byte{},
	}
	for id := range bundle.OneTimePreKeys {
		r.opkID = id
		break
	}
	return r, nil
}

// ensureSendingChain creates a fresh sending ratchet pair when the old
// chain was retired (after a remote ratchet step). One root KDF step.
func (r *Ratchet) ensureSendingChain() error {
	if r.sendingChain != nil {
		return nil
	}
	if !r.haveRecvPub {
		return errors.New("e2e: no remote ratchet key yet")
	}
	nk, err := NewKeyPair()
	if err != nil {
		return err
	}
	out, err := dh(nk, r.recvPub[:])
	if err != nil {
		return err
	}
	r.rootKey, r.sendingChain = kdfRoot(r.rootKey, out)
	r.sendingDH = nk
	r.sendingCounter = 0
	r.previousCounter = r.retiredSendCount
	return nil
}

// Encrypt seals plaintext into an envelope.
func (r *Ratchet) Encrypt(plaintext []byte) (Envelope, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureSendingChain(); err != nil {
		return Envelope{}, err
	}
	env := Envelope{
		Version:    1,
		Type:       EnvRatchet,
		RatchetPub: r.sendingDH.Public(),
		PrevCount:  r.previousCounter,
		Counter:    r.sendingCounter,
	}
	if r.isInitiator && !r.initSent {
		env.Type = EnvInit
		env.IdentityPub = r.selfDH
		env.IdentitySigPub = r.selfSig
		env.IdentityCert = r.selfCert()
		env.RegID = r.selfID
		env.OpkID = r.opkID
		hdr := pb.NewBuilder().Bytes(1, initTag).Uint(2, uint64(r.spkID)).Build()
		var err error
		env.HeaderEncrypt, err = encryptHeader(r.rootKey, hdr)
		if err != nil {
			return Envelope{}, err
		}
		r.initSent = true
	}
	msgKey, next := kdfChain(r.sendingChain)
	r.sendingChain = next
	aesKey, iv := expandMessageKey(msgKey)
	env.Body = aesGCMEncrypt(aesKey, iv, plaintext, envAAD(env))
	r.sendingCounter++
	return env, nil
}

func (r *Ratchet) selfCert() []byte {
	if r.signer == nil {
		return nil
	}
	return r.signer(idCertMessage(r.selfDH))
}

// Decrypt opens a received envelope.
func (r *Ratchet) Decrypt(env Envelope) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var pub [32]byte
	copy(pub[:], env.RatchetPub)
	if r.recvChain == nil || pub != r.recvPub {
		if err := r.recvRatchetStep(pub, env.PrevCount); err != nil {
			return nil, err
		}
	}
	return r.openMessage(env, pub)
}

// recvRatchetStep consumes a new remote ratchet key: skip the remainder
// of the old receiving chain, then a single root KDF step. Our current
// sending chain retires (its message count becomes prevCount for the new
// chain we create on next Encrypt).
func (r *Ratchet) recvRatchetStep(pub [32]byte, pn uint32) error {
	if r.recvChain != nil {
		for r.receivingCounter < pn {
			if len(r.skipped) >= r.maxSkip {
				return errors.New("e2e: skipped key buffer exhausted")
			}
			mk, next := kdfChain(r.recvChain)
			r.skipped[chainIndex{Ratchet: r.recvPub, PN: r.previousCounter, N: r.receivingCounter}] = mk
			r.recvChain = next
			r.receivingCounter++
		}
	}
	// Retire our sending chain (its message count becomes prevCount for
	// the new chain we create on next Encrypt).
	if r.sendingChain != nil {
		r.retiredSendCount = r.sendingCounter
	}
	r.sendingChain = nil
	if r.sendingDH == nil {
		return errors.New("e2e: cannot ratchet without a sending identity yet")
	}
	out, err := dh(r.sendingDH, pub[:])
	if err != nil {
		return err
	}
	r.rootKey, r.recvChain = kdfRoot(r.rootKey, out)
	r.receivingCounter = 0
	copy(r.recvPub[:], pub[:])
	r.haveRecvPub = true
	return nil
}

// openMessage derives/uses the message key for env.
func (r *Ratchet) openMessage(env Envelope, pub [32]byte) ([]byte, error) {
	idx := chainIndex{Ratchet: pub, PN: env.PrevCount, N: env.Counter}
	if sk, ok := r.skipped[idx]; ok {
		delete(r.skipped, idx)
		return r.openWithKey(sk, env)
	}
	if env.Counter < r.receivingCounter {
		return nil, errors.New("e2e: message too old (counter behind chain)")
	}
	for r.receivingCounter < env.Counter {
		if len(r.skipped) >= r.maxSkip {
			return nil, errors.New("e2e: skipped key buffer exhausted")
		}
		mk, next := kdfChain(r.recvChain)
		r.skipped[chainIndex{Ratchet: pub, PN: env.PrevCount, N: r.receivingCounter}] = mk
		r.recvChain = next
		r.receivingCounter++
	}
	mk, next := kdfChain(r.recvChain)
	r.recvChain = next
	r.receivingCounter++
	return r.openWithKey(mk, env)
}

func (r *Ratchet) openWithKey(msgKey []byte, env Envelope) ([]byte, error) {
	aesKey, iv := expandMessageKey(msgKey)
	return aesGCMDecrypt(aesKey, iv, env.Body, envAAD(env))
}

// envAAD binds ratchet pub + header to the ciphertext.
func envAAD(env Envelope) []byte {
	return bytes.Join([][]byte{env.RatchetPub, env.HeaderEncrypt}, nil)
}

// PeerIdentity returns the authenticated peer's identity material.
func (r *Ratchet) PeerIdentity() (dhPub, sigPub []byte, regID uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte{}, r.peerIdentityPub...), append([]byte{}, r.peerSigPub...), r.peerRegID
}

// ---------------------------------------------------------------------------
// Bob side

// BobKeys are the responder's private X3DH inputs.
type BobKeys struct {
	Identity     *Identity
	SignedPreKey *KeyPair
	SignedPreID  uint32
	OneTimeKey   *KeyPair // nil if unused
	OneTimeKeyID uint32
}

// BobSession accepts an incoming init envelope (first message from a
// stranger) and returns the established ratchet plus decrypted payload.
func BobSession(keys BobKeys, env Envelope, info []byte) (*Ratchet, []byte, error) {
	if env.Type != EnvInit {
		return nil, nil, errors.New("e2e: not an init envelope")
	}
	if len(env.IdentityPub) != 32 || len(env.IdentitySigPub) != ed25519.PublicKeySize {
		return nil, nil, ErrBadKey
	}
	if !ed25519.Verify(env.IdentitySigPub, idCertMessage(env.IdentityPub), env.IdentityCert) {
		return nil, nil, errors.New("e2e: sender identity certificate invalid")
	}
	root, chain, err := X3DHRecipient(keys.Identity.DH, keys.SignedPreKey,
		env.IdentityPub, env.RatchetPub, keys.OneTimeKey, info)
	if err != nil {
		return nil, nil, err
	}
	r := &Ratchet{
		rootKey:         root,
		recvChain:       chain,
		initInfo:        info,
		maxSkip:         MaxSkippedMessageKeys,
		skipped:         map[chainIndex][]byte{},
		isInitiator:     false,
		peerIdentityPub: env.IdentityPub,
		peerSigPub:      env.IdentitySigPub,
		peerRegID:       env.RegID,
		opkID:           env.OpkID,
		spkID:           keys.SignedPreID,
		selfDH:          keys.Identity.DH.Public(),
		selfSig:         keys.Identity.SignPub,
		selfID:          keys.Identity.RegID,
		signer:          keys.Identity.Sign,
	}
	copy(r.recvPub[:], env.RatchetPub)
	r.haveRecvPub = true
	// Validate init header tag under the root key (proves correct X3DH).
	hdr, err := decryptHeader(r.rootKey, env.HeaderEncrypt)
	if err != nil {
		return nil, nil, err
	}
	m, err := pb.Parse(hdr)
	if err != nil {
		return nil, nil, err
	}
	if tag, _ := m.GetBytes(1); !bytes.Equal(tag, initTag) {
		return nil, nil, errors.New("e2e: bad init header tag")
	}
	if spkID, ok := m.GetUint(2); ok && uint32(spkID) != keys.SignedPreID {
		return nil, nil, errors.New("e2e: signed prekey id mismatch")
	}
	msg, err := r.openMessage(env, r.recvPub)
	if err != nil {
		return nil, nil, err
	}
	return r, msg, nil
}

// ---------------------------------------------------------------------------
// serialization

type persistedRatchet struct {
	Version          int      `json:"v"`
	RootKey          b64      `json:"root"`
	SendingChain     b64      `json:"send_chain,omitempty"`
	RecvChain        b64      `json:"recv_chain,omitempty"`
	SendingDHSeed    b64      `json:"send_dh,omitempty"`
	RecvPub          b64      `json:"recv_pub"`
	HaveRecvPub      bool     `json:"have_pub"`
	InitSent         bool     `json:"init_sent"`
	IsInitiator      bool     `json:"is_init"`
	SendingCounter   uint32   `json:"sc"`
	ReceivingCounter uint32   `json:"rc"`
	PreviousCounter  uint32   `json:"pc"`
	RetiredSendCount uint32   `json:"rsc"`
	PeerIdentity     b64      `json:"peer"`
	PeerSig          b64      `json:"peer_sig"`
	PeerRegID        uint32   `json:"peer_reg"`
	OpkID            uint32   `json:"opk"`
	SpkID            uint32   `json:"spk"`
	InitInfo         b64      `json:"info"`
	SelfDH           b64      `json:"self_dh"`
	SelfSig          b64      `json:"self_sig"`
	SelfRegID        uint32   `json:"self_reg"`
	Skipped          []skipKV `json:"skipped"`
}

type skipKV struct {
	Key b64    `json:"k"`
	PN  uint32 `json:"pn"`
	N   uint32 `json:"n"`
	V   b64    `json:"v"`
}

// b64 wraps []byte for JSON.
type b64 []byte

func (b b64) MarshalJSON() ([]byte, error) {
	return []byte(`"` + base64.StdEncoding.EncodeToString(b) + `"`), nil
}

func (b *b64) UnmarshalJSON(data []byte) error {
	data = bytes.Trim(data, `"`)
	out, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	*b = out
	return nil
}

// MarshalState serializes the ratchet for storage (trusted tier).
func (r *Ratchet) MarshalState() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := persistedRatchet{
		Version: 1, RootKey: r.rootKey, SendingChain: r.sendingChain,
		RecvChain: r.recvChain, RecvPub: r.recvPub[:], HaveRecvPub: r.haveRecvPub,
		InitSent: r.initSent, IsInitiator: r.isInitiator,
		SendingCounter: r.sendingCounter, ReceivingCounter: r.receivingCounter,
		PreviousCounter: r.previousCounter, RetiredSendCount: r.retiredSendCount,
		PeerIdentity: r.peerIdentityPub, PeerSig: r.peerSigPub,
		PeerRegID: r.peerRegID, OpkID: r.opkID, SpkID: r.spkID,
		InitInfo: r.initInfo, SelfDH: r.selfDH, SelfSig: r.selfSig,
		SelfRegID: r.selfID,
	}
	if r.sendingDH != nil {
		p.SendingDHSeed = r.sendingDH.Seed()
	}
	for idx, key := range r.skipped {
		p.Skipped = append(p.Skipped, skipKV{Key: idx.Ratchet[:], PN: idx.PN, N: idx.N, V: key})
	}
	return json.Marshal(p)
}

// RestoreRatchet reloads a serialized session. The identity signer is not
// persisted (init was already sent); re-init requires a fresh session.
func RestoreRatchet(raw []byte) (*Ratchet, error) {
	var p persistedRatchet
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Version != 1 {
		return nil, errors.New("e2e: unsupported state version")
	}
	r := &Ratchet{
		rootKey: p.RootKey, sendingChain: p.SendingChain, recvChain: p.RecvChain,
		sendingCounter: p.SendingCounter, receivingCounter: p.ReceivingCounter,
		previousCounter: p.PreviousCounter, retiredSendCount: p.RetiredSendCount,
		initSent: p.InitSent, isInitiator: p.IsInitiator,
		haveRecvPub:     p.HaveRecvPub,
		peerIdentityPub: p.PeerIdentity, peerSigPub: p.PeerSig,
		peerRegID: p.PeerRegID, opkID: p.OpkID, spkID: p.SpkID,
		initInfo: p.InitInfo, selfDH: p.SelfDH, selfSig: p.SelfSig,
		selfID:  p.SelfRegID,
		maxSkip: MaxSkippedMessageKeys,
		skipped: map[chainIndex][]byte{},
	}
	copy(r.recvPub[:], p.RecvPub)
	if len(p.SendingDHSeed) > 0 {
		dhPair, err := KeyPairFromSeed(p.SendingDHSeed)
		if err != nil {
			return nil, err
		}
		r.sendingDH = dhPair
	}
	for _, kv := range p.Skipped {
		var idx chainIndex
		copy(idx.Ratchet[:], kv.Key)
		idx.PN, idx.N = kv.PN, kv.N
		cp := make([]byte, len(kv.V))
		copy(cp, kv.V)
		r.skipped[idx] = cp
	}
	return r, nil
}

// NewBobKeys creates responder material plus the public bundle to publish.
func NewBobKeys() (BobKeys, *PreKeyBundle, error) {
	id, err := NewIdentity()
	if err != nil {
		return BobKeys{}, nil, err
	}
	spk, err := NewKeyPair()
	if err != nil {
		return BobKeys{}, nil, err
	}
	var sid [4]byte
	if _, err := randRead(sid[:]); err != nil {
		return BobKeys{}, nil, err
	}
	spkID := uint32(sid[0])<<24 | uint32(sid[1])<<16 | uint32(sid[2])<<8 | uint32(sid[3])
	opk, err := NewKeyPair()
	if err != nil {
		return BobKeys{}, nil, err
	}
	var oid [4]byte
	if _, err := randRead(oid[:]); err != nil {
		return BobKeys{}, nil, err
	}
	opkID := uint32(oid[0])<<24 | uint32(oid[1])<<16 | uint32(oid[2])<<8 | uint32(oid[3])
	bundle := BuildBundle(id, spk, spkID, map[uint32][]byte{opkID: opk.Public()})
	return BobKeys{
		Identity:     id,
		SignedPreKey: spk,
		SignedPreID:  spkID,
		OneTimeKey:   opk,
		OneTimeKeyID: opkID,
	}, bundle, nil
}
