// Package api is BaturWhatsApi's public façade: application developers
// create a Batur instance, register sessions, send/observe messages through
// stable domain models. Protocol internals (binary.Node, noise, transport)
// are deliberately not exposed here.
package api

import (
	"context"
	"errors"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
	"github.com/ibradecode/baturwhatsapi/supervisor"
	"github.com/ibradecode/baturwhatsapi/transport"
)

// Errors.
var (
	ErrUnknownSession  = errors.New("batur: unknown session")
	ErrAlreadyAttached = errors.New("batur: session id already attached")
	ErrNotOnline       = errors.New("batur: session not online")
	ErrNotImplemented  = errors.New("batur: not implemented in this engine revision")
)

// Connection states (public mirror of the state machine).
const (
	StateStopped        = string(statemachine.Stopped)
	StateConnecting     = string(statemachine.Connecting)
	StateAuthenticating = string(statemachine.Authenticating)
	StateSyncing        = string(statemachine.Syncing)
	StateOnline         = string(statemachine.Online)
	StateDegraded       = string(statemachine.Degraded)
	StateReconnecting   = string(statemachine.Reconnecting)
	StateError          = string(statemachine.Error)
)

// Target identifies a chat/endpoint.
type Target struct {
	JID string // canonical string form, e.g. "628123@s.whatsapp.net"
}

// Message is the public domain model for a message (v0.1: metadata + text;
// encrypted payloads arrive with the Signal engine in Phase 2).
type Message struct {
	ID       string
	Chat     Target
	Sender   Target
	Text     string
	Type     string
	Stamp    time.Time
	FromMe   bool
	RawAttrs map[string]string
}

// SessionStatus is the public health view of one session.
type SessionStatus struct {
	ID         string
	State      string
	Retries    int
	LastOnline time.Time
	Account    string
}

// Options configure a Batur instance.
type Options struct {
	// BundleSource resolves peers for encrypted sending (SendText).
	BundleSource BundleSource
	// Store persists session credentials across restarts. Defaults to an
	// in-memory store.
	Store storage.KV
	// Bus is the event bus; one is created if nil. Close() only closes a
	// bus the instance created itself.
	Bus *events.Bus
	// Dict overrides the protocol token dictionary.
	Dict *token.Dictionary
	// MasterKey (32 bytes) seals all stored values at rest (AES-256-GCM).
	MasterKey []byte
	// Recovery tuning.
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	StableReset time.Duration
}

// Batur is the engine entrypoint.
type Batur struct {
	opts    Options
	bus     *events.Bus
	owns    bool
	sup     *supervisor.Supervisor
	dict    *token.Dictionary
	sess    map[string]*session.Session
	bundles BundleSource
}

// New creates an engine instance.
func New(opts Options) (*Batur, error) {
	if opts.Store == nil {
		opts.Store = storage.NewMemory()
	}
	if len(opts.MasterKey) > 0 {
		sealed, err := storage.NewSecureKV(opts.Store, opts.MasterKey)
		if err != nil {
			return nil, err
		}
		opts.Store = sealed
	}
	bus := opts.Bus
	owns := false
	if bus == nil {
		bus = events.New()
		owns = true
	}
	dict := opts.Dict
	if dict == nil {
		dict = token.Default()
	}
	sv := supervisor.New(supervisor.Options{
		Bus:         bus,
		Store:       opts.Store,
		BaseBackoff: opts.BaseBackoff,
		MaxBackoff:  opts.MaxBackoff,
		StableReset: opts.StableReset,
	})
	return &Batur{
		opts: opts, bus: bus, owns: owns, sup: sv, dict: dict,
		sess: map[string]*session.Session{}, bundles: opts.BundleSource,
	}, nil
}

// Bus exposes the event bus for subscriptions.
func (b *Batur) Bus() *events.Bus { return b.bus }

// Attach registers a session with the fleet. dialer connects the session to
// the control socket (production: transport/ws dialer; tests: mock dialer).
// auth verifies the server's static key; it must not be nil.
func (b *Batur) Attach(id string, dialer transport.Dialer, auth session.ServerAuth, device session.DeviceInfo) error {
	if id == "" {
		return errors.New("batur: empty session id")
	}
	if _, dup := b.sess[id]; dup {
		return ErrAlreadyAttached
	}
	sopts := session.Options{
		ID: id, Dialer: dialer, Dict: b.dict, Store: b.opts.Store, Bus: b.bus,
		Device: device,
	}
	cfg := supervisor.Config{Session: sopts, Auth: auth}
	if err := b.sup.Add(cfg); err != nil {
		return err
	}
	b.sess[id] = nil // lifecycle owned by supervisor
	return nil
}

// Detach removes a session from the fleet (stops it cleanly).
func (b *Batur) Detach(ctx context.Context, id string) error {
	if _, ok := b.sess[id]; !ok {
		return ErrUnknownSession
	}
	delete(b.sess, id)
	return b.sup.Remove(ctx, id)
}

// RequestNode performs a raw protocol IQ request against one session
// (bridge capability for the HTTP API / advanced SDKs).
func (b *Batur) RequestNode(ctx context.Context, id string, n binary.Node) (binary.Node, error) {
	sess := b.sup.Session(id)
	if sess == nil {
		return binary.Node{}, ErrUnknownSession
	}
	return sess.Request(ctx, n)
}

// Start begins supervising all attached sessions.
func (b *Batur) Start(ctx context.Context) error { return b.sup.Start(ctx) }

// Stop shuts down the fleet and (if owned) the event bus.
func (b *Batur) Stop(ctx context.Context) error {
	err := b.sup.Stop(ctx)
	if b.owns {
		b.bus.Close()
	}
	return err
}

// Status reports one session's health.
func (b *Batur) Status(id string) (SessionStatus, error) {
	h, ok := b.sup.Health()[id]
	if !ok {
		return SessionStatus{}, ErrUnknownSession
	}
	return SessionStatus{
		ID: h.ID, State: string(h.State), Retries: h.Retries,
		LastOnline: h.LastOnline, Account: h.Creds.AccountJID,
	}, nil
}

// Sessions lists attached session ids.
func (b *Batur) Sessions() []string { return b.sup.Sessions() }

// Subscribe helpers -------------------------------------------------------

// OnMessage registers a handler for messages received on sessionID (""
// matches all sessions). The callback receives the public Message model.
func (b *Batur) OnMessage(ctx context.Context, sessionID string, h func(context.Context, Message)) (*events.Subscription, error) {
	return b.bus.Subscribe(events.MessageReceived, 256, events.PolicyBlock,
		func(c context.Context, ev events.Event) {
			if sessionID != "" && ev.Session != sessionID {
				return
			}
			if node, ok := ev.Data.(binary.Node); ok {
				h(c, toMessage(node, ev.Session))
			}
		})
}

// OnConnectionState registers a handler for state transitions.
func (b *Batur) OnConnectionState(ctx context.Context, sessionID string, h func(context.Context, string, string)) (*events.Subscription, error) {
	return b.bus.Subscribe(events.ConnectionState, 256, events.PolicyBlock,
		func(c context.Context, ev events.Event) {
			if sessionID != "" && ev.Session != sessionID {
				return
			}
			if st, ok := ev.Data.(statemachine.State); ok {
				h(c, ev.Session, string(st))
			}
		})
}

// toMessage maps the protocol node to the public domain model (protocol
// models never escape this package boundary; only normalized fields do).
func toMessage(n binary.Node, sessID string) Message {
	m := Message{Stamp: time.Now().UTC()}
	m.ID, _ = n.StringAttr("id")
	m.Type, _ = n.StringAttr("type")
	m.Chat = Target{JID: n.MustStringAttr("from")}
	m.Sender = Target{JID: n.MustStringAttr("participant")}
	if m.Sender.JID == "" {
		m.Sender.JID = m.Chat.JID
	}
	if child, ok := n.ChildByTag("plain"); ok {
		m.Text, _ = child.TextContent()
	} else if txt, ok := n.TextContent(); ok {
		m.Text = txt
	}
	m.RawAttrs = map[string]string{}
	for k := range n.Attrs {
		v, _ := n.StringAttr(k)
		m.RawAttrs[k] = v
	}
	return m
}
