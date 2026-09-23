// e2e messaging wiring for the api layer: resolves peer bundles, keeps
// per-target Double Ratchet state in the engine storage, and encrypts
// outbound text into protocol message nodes.
//
// The peer model mirrors WhatsApp: the server relays opaque envelopes and
// only endpoints hold ratchet state. Works against the mock server today;
// after T-102 the same flow maps onto WhatsApp's SignalMessage wire.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/security/e2e"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/storage"
)

// e2eInfo binds derivations to this protocol revision.
var e2eInfo = e2e.ProtocolInfoV1

// BundleSource resolves a target JID to its X3DH prekey bundle.
type BundleSource func(ctx context.Context, target Target) (*e2e.PreKeyBundle, error)

// ErrNoBundleSource is returned when SendText is used without one.
var ErrNoBundleSource = errors.New("batur: no BundleSource configured")

// e2eKey is the storage path for one ratchet.
func e2eKey(sessionID, target string) string {
	return "session/" + sessionID + "/e2e/" + target
}

// SendText encrypts text into the peer's ratchet and sends a message node.
// Returns the assigned message id.
func (b *Batur) SendText(ctx context.Context, sessionID string, to Target, text string) (string, error) {
	sess := b.sup.Session(sessionID)
	if sess == nil {
		return "", ErrUnknownSession
	}
	if to.JID == "" {
		return "", errors.New("batur: empty target")
	}
	creds := sess.Credentials()
	if len(creds.IdentitySeed) == 0 || len(creds.IdentitySigSeed) == 0 {
		return "", fmt.Errorf("%w: identity not provisioned", ErrNotOnline)
	}
	key := e2eKey(sessionID, to.JID)
	rt, err := b.loadRatchet(ctx, creds, key, to)
	if err != nil {
		return "", err
	}
	env, err := rt.Encrypt([]byte(text))
	if err != nil {
		return "", err
	}
	state, err := rt.MarshalState()
	if err != nil {
		return "", err
	}
	msgID := newMsgID()
	node := binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id":   msgID,
			"to":   to.JID,
			"type": "text",
		},
		Content: []binary.Node{{Tag: "e2e", Content: env.Serialize()}},
	}
	if err := sess.Send(ctx, node); err != nil {
		return "", err
	}
	// Persist after a successful send so ratchet counters never advance
	// ahead of wire state on crash.
	if err := b.opts.Store.Set(ctx, key, state); err != nil {
		return "", fmt.Errorf("batur: persist ratchet: %w", err)
	}
	_ = b.bus.Publish(ctx, events.Event{
		Type: events.MessageSent, Session: sessionID,
		Data: Message{ID: msgID, Chat: to, Text: text, Type: "text",
			Stamp: time.Now().UTC(), FromMe: true},
	})
	return msgID, nil
}

// loadRatchet restores (or first-creates) the Double Ratchet for a target.
func (b *Batur) loadRatchet(ctx context.Context, creds session.Credentials, key string, to Target) (*e2e.Ratchet, error) {
	raw, err := b.opts.Store.Get(ctx, key)
	if err == nil {
		return e2e.RestoreRatchet(raw)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	if b.bundles == nil {
		return nil, ErrNoBundleSource
	}
	bundle, err := b.bundles(ctx, to)
	if err != nil {
		return nil, fmt.Errorf("batur: resolve bundle: %w", err)
	}
	ident, err := e2e.RestoreIdentity(creds.IdentitySeed, creds.IdentitySigSeed, creds.RegistrationID)
	if err != nil {
		return nil, err
	}
	return e2e.AliceSession(bundle, ident, e2eInfo)
}

// newMsgID returns a random 16-char base32 message id.
func newMsgID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}
