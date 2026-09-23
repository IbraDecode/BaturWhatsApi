// Package session implements the per-device connection engine: it owns one
// transport, one noise cipher pair, one protocol decode loop, one state
// machine and one persistence slice. Sessions are fully isolated; the
// supervisor runs many of them.
//
// Concurrency contract: exactly one goroutine ever reads from the transport.
// The handshake phase reads raw frames directly; after authentication the
// same goroutine keeps reading, decrypting and dispatching. Writers (Send /
// keep-alive) run on other goroutines.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/wapb"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/noise"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
	"github.com/ibradecode/baturwhatsapi/transport"
)

// Errors.
var (
	ErrStopped        = errors.New("session: stopped")
	ErrNotOnline      = errors.New("session: not online")
	ErrTimeout        = errors.New("session: timeout")
	ErrServerRejected = errors.New("session: server rejected handshake")
	ErrNoDialer       = errors.New("session: no dialer configured")
)

// Options configures a Session.
type Options struct {
	ID             string
	Dialer         transport.Dialer
	Dict           *token.Dictionary
	Store          storage.KV
	Bus            *events.Bus
	Logger         *slog.Logger
	Device         DeviceInfo
	PingEvery      time.Duration // default 20s once online
	StaleAfter     time.Duration // inbound silence that marks DEGRADED; default 2*PingEvery
	RequestTimeout time.Duration // default 60s
}

// DeviceInfo is the registration metadata sent inside the finish payload.
type DeviceInfo struct {
	Platform   string // "web" | "desktop"
	DeviceName string
	Browser    string
	Version    string
	Make       string
	Model      string
	OSVersion  string
}

// Credentials is the persistent identity of one session. Generated on first
// registration, restored from storage afterwards; surviving process
// restarts is a hard requirement of the engine.
type Credentials struct {
	NoiseKeySeed   []byte `json:"noise_key"`
	IdentitySeed   []byte `json:"identity_key"`
	RegistrationID uint32 `json:"reg_id"`
	DeviceID       string `json:"device_id,omitempty"`
	AccountJID     string `json:"account,omitempty"`
	ServerStatic   []byte `json:"server_static,omitempty"`
}

func generateCredentials() (*Credentials, error) {
	noiseKP, err := noise.NewKeyPair()
	if err != nil {
		return nil, err
	}
	idKP, err := noise.NewKeyPair()
	if err != nil {
		return nil, err
	}
	var reg [4]byte
	if _, err := rand.Read(reg[:]); err != nil {
		return nil, err
	}
	return &Credentials{
		NoiseKeySeed:   noiseKP.Seed(),
		IdentitySeed:   idKP.Seed(),
		RegistrationID: uint32(reg[0])<<24 | uint32(reg[1])<<16 | uint32(reg[2])<<8 | uint32(reg[3]),
	}, nil
}

// ServerAuth verifies the server static key + decrypted cert blob right
// after the noise handshake, before the client sends its own identity.
// Default engine behavior is fail-closed: nil means reject.
type ServerAuth func(staticPub, certBlob []byte) error

// Session is one device connection.
type Session struct {
	opts Options
	mach *statemachine.Machine

	creds *Credentials
	dict  *token.Dictionary

	conn         transport.Conn // set once dial succeeds; guarded by connMu
	writeMu      sync.Mutex     // serializes seal+send (wire order == counter order)
	connMu       sync.Mutex
	connReady    chan struct{} // closed when conn is dialed (or dial failed)
	broken       chan struct{} // closed once when the connection task ends
	brokenClosed bool
	breakErr     error
	online       chan struct{} // closed when ONLINE reached
	runErr       chan error    // final error of the connection task (buffered)

	mu            sync.RWMutex
	send          *noise.Cipher
	recv          *noise.Cipher
	requests      map[string]chan binary.Node
	lastIn        time.Time
	stopC         chan struct{}
	stopRequested bool
	stopping      bool
	stopped       bool

	ServerAuth ServerAuth
	log        *slog.Logger
}

// New creates a session.
func New(opts Options) (*Session, error) {
	if opts.ID == "" {
		return nil, errors.New("session: empty id")
	}
	if opts.Dialer == nil {
		return nil, ErrNoDialer
	}
	if opts.Dict == nil {
		opts.Dict = token.Default()
	}
	if opts.Store == nil {
		opts.Store = storage.NewMemory()
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.PingEvery <= 0 {
		opts.PingEvery = 20 * time.Second
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = 2 * opts.PingEvery
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 60 * time.Second
	}
	s := &Session{
		opts:      opts,
		mach:      statemachine.NewMachine(),
		dict:      opts.Dict,
		connReady: make(chan struct{}),
		broken:    make(chan struct{}),
		online:    make(chan struct{}),
		runErr:    make(chan error, 1),
		requests:  map[string]chan binary.Node{},
		stopC:     make(chan struct{}),
		lastIn:    time.Now(),
		log:       opts.Logger.With("session", opts.ID),
	}
	return s, nil
}

// Machine exposes the state machine for supervisors/observability.
func (s *Session) Machine() *statemachine.Machine { return s.mach }

// State is a shortcut for Machine().State().
func (s *Session) State() statemachine.State { return s.mach.State() }

func (s *Session) emit(ctx context.Context, typ string, data any) {
	if b := s.opts.Bus; b != nil {
		_ = b.Publish(ctx, events.Event{Type: typ, Session: s.opts.ID, Data: data})
	}
}

// ---------------------------------------------------------------------------
// persistence

func (s *Session) credsKey() string { return "session/" + s.opts.ID + "/credentials" }

func (s *Session) loadCredentials(ctx context.Context) error {
	raw, err := s.opts.Store.Get(ctx, s.credsKey())
	if errors.Is(err, storage.ErrNotFound) {
		gen, gerr := generateCredentials()
		if gerr != nil {
			return gerr
		}
		s.creds = gen
		return s.saveCredentials(ctx)
	}
	if err != nil {
		return err
	}
	var c Credentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("session: corrupt credentials: %w", err)
	}
	s.creds = &c
	return nil
}

func (s *Session) saveCredentials(ctx context.Context) error {
	raw, err := json.Marshal(s.creds)
	if err != nil {
		return err
	}
	return s.opts.Store.Set(ctx, s.credsKey(), raw)
}

// Credentials returns a copy of the session identity.
func (s *Session) Credentials() Credentials {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.creds == nil {
		return Credentials{}
	}
	return *s.creds
}

// DeviceID is the stable device identifier derived from the session id.
func (s *Session) DeviceID() string {
	return sha1Short([]byte(s.opts.ID))
}

// ---------------------------------------------------------------------------
// lifecycle

// Start connects, authenticates and syncs; it returns when the session
// reaches ONLINE (error otherwise). On success the connection keeps running
// in background until it fails or Stop is called.
func (s *Session) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.stopped || s.stopping {
		s.mu.Unlock()
		return ErrStopped
	}
	s.mu.Unlock()

	if err := s.loadCredentials(ctx); err != nil {
		return err
	}
	if err := s.mach.Move(statemachine.Starting, "start"); err != nil {
		return err
	}
	s.emit(ctx, events.ConnectionState, s.State())
	go s.connectionTask(ctx)

	select {
	case <-s.online:
		return nil
	case err := <-s.runErr:
		if err == nil {
			err = errors.New("session: connection task exited")
		}
		return err
	case <-ctx.Done():
		s.abort()
		return ctx.Err()
	}
}

// connectionTask owns the socket read side for its entire lifetime.
func (s *Session) connectionTask(ctx context.Context) {
	var taskErr error
	defer func() {
		if taskErr != nil && !errors.Is(taskErr, ErrStopped) && ctx.Err() == nil {
			s.fail(taskErr)
		} else {
			s.shutdownOK()
		}
		s.abort()
		s.runErr <- taskErr
	}()

	// Dial.
	_ = s.mach.Move(statemachine.Connecting, "dial")
	s.emit(ctx, events.ConnectionState, s.State())
	dialCtx, cancelDial := context.WithTimeout(ctx, 30*time.Second)
	conn, err := s.opts.Dialer.Dial(dialCtx, "control")
	cancelDial()
	if err != nil {
		taskErr = fmt.Errorf("session: dial: %w", err)
		return
	}
	s.connMu.Lock()
	s.conn = conn
	s.connMu.Unlock()
	close(s.connReady)

	// Handshake (this goroutine is the sole reader).
	_ = s.mach.Move(statemachine.Authenticating, "noise")
	s.emit(ctx, events.ConnectionState, s.State())
	if err := s.handshake(ctx, conn); err != nil {
		taskErr = err
		return
	}

	// Connect IQ: responses now arrive via our own dispatch path. We must
	// start the decrypt-dispatch loop BEFORE issuing the IQ.
	_ = s.mach.Move(statemachine.Syncing, "connect-iq")
	s.emit(ctx, events.ConnectionState, s.State())
	frames := make(chan []byte, 64)
	go s.frameConsumer(ctx, frames)
	go s.serveFrames(ctx, conn, frames)
	if err := s.connectIQ(ctx); err != nil {
		taskErr = fmt.Errorf("session: connect iq: %w", err)
		return
	}
	if err := s.mach.Move(statemachine.Online, "connected"); err != nil {
		taskErr = err
		return
	}
	s.markInbound()
	s.emit(ctx, events.ConnectionState, s.State())
	s.emit(ctx, events.SessionReady, map[string]any{"device_id": s.DeviceID()})
	close(s.online)

	// Hand the read side fully to serveFrames; just watch for its end.
	go s.keepAliveLoop(ctx)
	select {
	case <-s.broken:
		s.connMu.Lock()
		be := s.breakErr
		s.connMu.Unlock()
		if be == nil {
			be = context.Canceled
		}
		taskErr = be
	case <-ctx.Done():
		taskErr = ctx.Err()
	}
}

// serveFrames decrypts and dispatches frames; single reader.
func (s *Session) serveFrames(ctx context.Context, conn transport.Conn, frames chan []byte) {
	for {
		raw, err := conn.ReceiveBinary(ctx)
		if err != nil {
			if ctx.Err() == nil && !s.isStopping() {
				s.log.Debug("read loop terminated", "err", err)
				s.fail(fmt.Errorf("session: transport: %w", err))
				return
			}
			s.shutdownOK()
			return
		}
		s.markInbound()
		select {
		case frames <- raw:
		default:
			// frame queue overflow should be impossible; drop loudly
			s.log.Warn("frame queue overflow")
		}
	}
}

func (s *Session) keepAliveLoop(ctx context.Context) {
	tick := time.NewTicker(s.opts.PingEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopC:
			return
		case <-tick.C:
		}
		st := s.mach.State()
		if st == statemachine.Error || st == statemachine.Stopping {
			return
		}
		if st != statemachine.Online && st != statemachine.Degraded {
			continue
		}
		if time.Since(s.inboundAt()) > s.opts.StaleAfter {
			_ = s.mach.Move(statemachine.Degraded, "inbound silence")
			s.emit(ctx, events.ConnectionState, s.State())
			s.fail(errors.New("session: inbound silence, recovering"))
			return
		}
		pingCtx, cancel := context.WithTimeout(ctx, s.opts.PingEvery)
		err := s.Send(pingCtx, binary.Node{
			Tag: "a", Attrs: binary.Attrs{"passive": "true", "xmlns": "urn:xmpp:whatsapp:ping", "id": NewRequestID()},
		})
		cancel()
		if err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// handshake (sole reader on conn until serveFrames takes over)

func (s *Session) handshake(ctx context.Context, conn transport.Conn) error {
	s.mu.RLock()
	seed := s.creds.NoiseKeySeed
	s.mu.RUnlock()
	noiseKP, err := noise.KeyPairFromSeed(seed)
	if err != nil {
		return err
	}
	xx, err := noise.NewXXClient(noiseKP, conn.BindingHeader())
	if err != nil {
		return err
	}
	ephC, err := xx.ClientHello1()
	if err != nil {
		return err
	}
	hello := wapb.WrapTop(wapb.HSFieldClientHello,
		(&wapb.ClientHello{Ephemeral: ephC}).Build())
	if err := conn.SendBinary(ctx, hello); err != nil {
		return err
	}
	resp, err := recvTimeout(ctx, conn, 20*time.Second)
	if err != nil {
		return err
	}
	shMsg, err := wapb.UnwrapTop(resp, wapb.HSFieldServerHello)
	if err != nil || shMsg == nil {
		return fmt.Errorf("%w: missing server hello", ErrServerRejected)
	}
	sh, err := wapb.ParseServerHello(shMsg)
	if err != nil || len(sh.Ephemeral) != 32 || len(sh.Static) == 0 {
		return fmt.Errorf("%w: malformed server hello", ErrServerRejected)
	}
	_, certPlain, err := xx.ReadServerHello(sh.Ephemeral, sh.Static, sh.Payload)
	if err != nil {
		return fmt.Errorf("session: server hello rejected: %w", err)
	}
	if s.ServerAuth == nil {
		return errors.New("session: ServerAuth policy not configured (refusing unverified server static key)")
	}
	if err := s.ServerAuth(xx.RemoteStatic(), certPlain); err != nil {
		return fmt.Errorf("session: server auth: %w", err)
	}
	s.mu.Lock()
	s.creds.ServerStatic = xx.RemoteStatic()
	s.mu.Unlock()
	if err := s.saveCredentials(ctx); err != nil {
		return err
	}
	finishPayload := s.finishPayload()
	clientStaticCT, clientPayloadCT, err := xx.WriteClientFinish(finishPayload)
	if err != nil {
		return err
	}
	finish := wapb.WrapTop(wapb.HSFieldClientFinish,
		(&wapb.ClientFinish{Static: clientStaticCT, Payload: clientPayloadCT}).Build())
	if err := conn.SendBinary(ctx, finish); err != nil {
		return err
	}
	send, recvCipher, err := xx.SendCipher()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.send, s.recv = send, recvCipher
	s.mu.Unlock()
	return nil
}

func (s *Session) finishPayload() []byte {
	s.mu.RLock()
	creds := s.creds
	s.mu.RUnlock()
	blob, _ := json.Marshal(map[string]any{
		"device_id": s.DeviceID(),
		"name":      s.opts.Device.DeviceName,
		"platform":  s.opts.Device.Platform,
		"reg_id":    creds.RegistrationID,
		"noise_pub": base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(creds.NoiseKeySeed[:32]),
	})
	return blob
}

func (s *Session) connectIQ(ctx context.Context) error {
	id := NewRequestID()
	node := binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"id": id, "type": "set", "to": "s.whatsapp.net"},
		Content: []binary.Node{{
			Tag: "config",
			Content: []binary.Node{{
				Tag:   "device",
				Attrs: binary.Attrs{"platform": s.opts.Device.Platform, "device_name": s.opts.Device.DeviceName},
			}},
		}},
	}
	resp, err := s.Request(ctx, node)
	if err != nil {
		return err
	}
	if acct, ok := resp.StringAttr("account"); ok && acct != "" {
		s.mu.Lock()
		s.creds.AccountJID = acct
		s.mu.Unlock()
		_ = s.saveCredentials(ctx)
	}
	return nil
}

// ---------------------------------------------------------------------------
// sending & requests

// Send writes an encrypted protocol node.
func (s *Session) Send(ctx context.Context, n binary.Node) error {
	s.mu.RLock()
	send := s.send
	s.mu.RUnlock()
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()
	if conn == nil || send == nil {
		return ErrNotOnline
	}
	plain := binary.MarshalDict(n, s.dict)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ct := send.Seal(nil, plain)
	return conn.SendBinary(ctx, ct)
}

// Request sends an IQ-style node and waits for the matching response id.
func (s *Session) Request(ctx context.Context, n binary.Node) (binary.Node, error) {
	if n.Attrs == nil {
		n.Attrs = binary.Attrs{}
	}
	id, _ := n.StringAttr("id")
	if id == "" {
		id = NewRequestID()
		n.Attrs["id"] = id
	}
	ch := make(chan binary.Node, 1)
	s.mu.Lock()
	if _, dup := s.requests[id]; dup {
		s.mu.Unlock()
		return binary.Node{}, fmt.Errorf("session: duplicate request id %q", id)
	}
	s.requests[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.requests, id)
		s.mu.Unlock()
	}()
	if err := s.Send(ctx, n); err != nil {
		return binary.Node{}, err
	}
	to := time.NewTimer(s.opts.RequestTimeout)
	defer to.Stop()
	select {
	case resp := <-ch:
		return resp, nil
	case <-to.C:
		return binary.Node{}, ErrTimeout
	case <-ctx.Done():
		return binary.Node{}, ctx.Err()
	case <-s.stopC:
		return binary.Node{}, ErrStopped
	case <-s.broken:
		return binary.Node{}, ErrNotOnline
	}
}

// NewRequestID returns a 12-char base32 request id.
func NewRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// ---------------------------------------------------------------------------
// dispatch

func (s *Session) dispatch(ctx context.Context, n binary.Node) {
	switch n.Tag {
	case "iq":
		id, _ := n.StringAttr("id")
		typ, _ := n.StringAttr("type")
		if id != "" && (typ == "result" || typ == "error") {
			s.mu.Lock()
			ch, ok := s.requests[id]
			s.mu.Unlock()
			if ok {
				select {
				case ch <- n:
				default:
				}
				return
			}
		}
		s.emit(ctx, events.ChatUpdated, n)
	case "message":
		s.emit(ctx, events.MessageReceived, n)
	case "receipt", "ack":
		s.emit(ctx, events.MessageAck, n)
	case "presence":
		s.emit(ctx, events.ContactUpdated, n)
	case "ib":
		s.handleInband(ctx, n)
	default:
		s.log.Debug("unhandled node", "tag", n.Tag)
	}
}

func (s *Session) handleInband(ctx context.Context, n binary.Node) {
	for _, child := range n.Children() {
		switch child.Tag {
		case "ack":
			if s.mach.State() == statemachine.Degraded {
				_ = s.mach.Move(statemachine.Online, "ib/ack")
				s.emit(ctx, events.ConnectionState, s.State())
			}
			s.emit(ctx, events.MessageAck, child)
		case "pair-device":
			s.emit(ctx, events.SessionReady, child)
		default:
			s.emit(ctx, events.ChatUpdated, child)
		}
	}
}

// decodeLoop converts raw frames to nodes: started by serveFrames consumer.
func (s *Session) frameConsumer(ctx context.Context, frames <-chan []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopC:
			return
		case raw, ok := <-frames:
			if !ok {
				return
			}
			s.mu.RLock()
			rc := s.recv
			s.mu.RUnlock()
			if rc == nil {
				continue
			}
			plain, err := rc.Open(nil, raw)
			if err != nil {
				s.fail(fmt.Errorf("session: frame decrypt failed: %w", err))
				return
			}
			node, err := binary.Decode(s.dict, plain)
			if err != nil {
				s.log.Warn("undecodable frame", "err", err, "bytes", len(plain))
				continue
			}
			s.dispatch(ctx, node)
		}
	}
}

// ---------------------------------------------------------------------------
// failure & shutdown

// fail records a hard connection failure once.
func (s *Session) fail(err error) {
	s.connMu.Lock()
	if !s.brokenClosed {
		s.brokenClosed = true
		s.breakErr = err
		close(s.broken)
	}
	s.connMu.Unlock()
	_ = s.mach.Move(statemachine.Error, err.Error())
	s.emit(context.Background(), events.ConnectionError, err.Error())
}

func (s *Session) shutdownOK() {
	s.connMu.Lock()
	if !s.brokenClosed {
		s.brokenClosed = true
		s.breakErr = ErrStopped
		close(s.broken)
	}
	s.connMu.Unlock()
}

// isStopping reports whether Stop/abort was requested.
func (s *Session) isStopping() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stopping
}

// abort is the internal fast shutdown (no clean stream teardown).
func (s *Session) abort() {
	s.mu.Lock()
	if s.stopRequested {
		s.mu.Unlock()
		return
	}
	s.stopRequested = true
	s.mu.Unlock()
	close(s.stopC)
	s.connMu.Lock()
	conn := s.conn
	s.conn = nil
	s.connMu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// Stop disconnects cleanly and marks the session stopped. A stopped session
// cannot be restarted (create a new one; identity persists in storage).
func (s *Session) Stop(ctx context.Context) error {
	s.mu.Lock()
	firstStop := !s.stopped
	s.stopped = true
	s.mu.Unlock()
	if !firstStop {
		return nil
	}
	_ = s.mach.Move(statemachine.Stopping, "stop")
	if err := s.mach.Move(statemachine.Stopping, "stop"); err != nil {
		s.mach.Force(statemachine.Stopping, "stop")
	}
	// Best-effort clean teardown before ripping the socket.
	sendCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = s.Send(sendCtx, binary.Node{Tag: "xmlstreamend"})
	cancel()
	s.abort()
	select {
	case <-s.broken:
	case <-ctx.Done():
	}
	_ = s.mach.Move(statemachine.Stopped, "stopped")
	s.emit(ctx, events.ConnectionState, s.State())
	return nil
}

// Done is closed when the connection task fully exits (online or failed).
// Supervisors use it to detect death of a previously ONLINE session.
func (s *Session) Done() <-chan struct{} { return s.broken }

// ---------------------------------------------------------------------------
// small helpers

func (s *Session) markInbound() {
	s.mu.Lock()
	s.lastIn = time.Now()
	s.mu.Unlock()
}

func (s *Session) inboundAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastIn
}
