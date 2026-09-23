// Package supervisor owns the 24/7 runtime: it keeps a fleet of sessions
// alive through automatic reconnect with exponential backoff + jitter,
// watches connection/session/storage health, and reports aggregated
// status. Failure classification drives policy: auth-rejected sessions back
// off hard; transient transport failures recover fast.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
)

// ErrNoSessions is returned by Run with an empty fleet.
var ErrNoSessions = errors.New("supervisor: no sessions")

// Options tunes recovery behavior.
type Options struct {
	Bus            *events.Bus
	Logger         *slog.Logger
	Store          storage.KV    // shared default; per-session overrides win
	BaseBackoff    time.Duration // default 1s
	MaxBackoff     time.Duration // default 60s
	Jitter         float64       // default 0.2 (±20%)
	StableReset    time.Duration // ONLINE for this long resets backoff (default 2m)
	DialTimeout    time.Duration // default 30s
	StuckThreshold time.Duration // state dwell limit (default 2m) → force retry
}

func (o *Options) withDefaults() {
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 60 * time.Second
	}
	if o.Jitter <= 0 {
		o.Jitter = 0.2
	}
	if o.StableReset <= 0 {
		o.StableReset = 2 * time.Minute
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 30 * time.Second
	}
	if o.StuckThreshold <= 0 {
		o.StuckThreshold = 2 * time.Minute
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Config is one supervised session.
type Config struct {
	Session session.Options
	Auth    session.ServerAuth
}

type managed struct {
	cfg    Config
	sess   *session.Session
	cancel context.CancelFunc
}

// Supervisor supervises a session fleet.
type Supervisor struct {
	opts Options

	mu        sync.Mutex
	sessions  map[string]*managed
	runCtx    context.Context
	runCancel context.CancelFunc
	wg        sync.WaitGroup

	// counters for health
	retries    map[string]int
	lastOnline map[string]time.Time
	phase      map[string]string // "backoff" while waiting to retry
}

// New builds a supervisor.
func New(opts Options) *Supervisor {
	opts.withDefaults()
	return &Supervisor{
		opts:       opts,
		sessions:   map[string]*managed{},
		retries:    map[string]int{},
		lastOnline: map[string]time.Time{},
		phase:      map[string]string{},
	}
}

// Add registers (and, when running, starts supervising) a session.
func (sv *Supervisor) Add(cfg Config) error {
	if cfg.Session.ID == "" {
		return errors.New("supervisor: session id required")
	}
	sv.mu.Lock()
	defer sv.mu.Unlock()
	if _, dup := sv.sessions[cfg.Session.ID]; dup {
		return fmt.Errorf("supervisor: session %q already registered", cfg.Session.ID)
	}
	if cfg.Session.Store == nil {
		cfg.Session.Store = sv.opts.Store
	}
	if cfg.Session.Bus == nil {
		cfg.Session.Bus = sv.opts.Bus
	}
	m := &managed{cfg: cfg}
	sv.sessions[cfg.Session.ID] = m
	if sv.runCtx != nil {
		ctx, cancel := context.WithCancel(sv.runCtx)
		m.cancel = cancel
		sv.spawn(ctx, m)
	}
	return nil
}

// Remove stops and deregisters a session.
func (sv *Supervisor) Remove(ctx context.Context, id string) error {
	sv.mu.Lock()
	m, ok := sv.sessions[id]
	if ok {
		delete(sv.sessions, id)
	}
	sv.mu.Unlock()
	if !ok {
		return fmt.Errorf("supervisor: unknown session %q", id)
	}
	if m.cancel != nil {
		m.cancel()
	}
	sv.mu.Lock()
	sess := m.sess
	sv.mu.Unlock()
	if sess != nil {
		return sess.Stop(ctx)
	}
	return nil
}

// Start begins supervising all registered sessions.
func (sv *Supervisor) Start(ctx context.Context) error {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	if sv.runCtx != nil {
		return errors.New("supervisor: already running")
	}
	if len(sv.sessions) == 0 {
		return ErrNoSessions
	}
	sv.runCtx, sv.runCancel = context.WithCancel(ctx)
	for _, m := range sv.sessions {
		cctx, cancel := context.WithCancel(sv.runCtx)
		m.cancel = cancel
		sv.spawn(cctx, m)
	}
	sv.opts.Logger.Info("supervisor started", "sessions", len(sv.sessions))
	return nil
}

// Stop halts all sessions and supervisory loops.
func (sv *Supervisor) Stop(ctx context.Context) error {
	sv.mu.Lock()
	if sv.runCancel != nil {
		sv.runCancel()
	}
	mg := make([]*managed, 0, len(sv.sessions))
	for _, m := range sv.sessions {
		mg = append(mg, m)
	}
	sv.mu.Unlock()
	var lastErr error
	for _, m := range mg {
		if m.cancel != nil {
			m.cancel()
		}
		if m.sess != nil {
			if err := m.sess.Stop(ctx); err != nil {
				lastErr = err
			}
		}
	}
	sv.wg.Wait()
	sv.opts.Logger.Info("supervisor stopped")
	return lastErr
}

// spawn runs the manage loop for one session with automatic recovery.
func (sv *Supervisor) spawn(ctx context.Context, m *managed) {
	sv.wg.Add(1)
	go func() {
		defer sv.wg.Done()
		sv.manageLoop(ctx, m)
	}()
}

func (sv *Supervisor) manageLoop(ctx context.Context, m *managed) {
	backoff := sv.opts.BaseBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		err := sv.attempt(ctx, m, &backoff)
		if ctx.Err() != nil {
			return // intentional shutdown
		}
		if err == nil {
			err = errors.New("session ended")
		}
		sv.emitAction(ctx, m.cfg.Session.ID, "retry", err.Error())
		wait := sv.jittered(backoff)
		sv.opts.Logger.Warn("reconnecting",
			"session", m.cfg.Session.ID, "in", wait, "reason", err)
		sv.mu.Lock()
		sv.retries[m.cfg.Session.ID]++
		sv.phase[m.cfg.Session.ID] = "backoff"
		sv.mu.Unlock()
		backoff = sv.nextBackoff(backoff)
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return
		}
		sv.mu.Lock()
		delete(sv.phase, m.cfg.Session.ID)
		sv.mu.Unlock()
	}
}

// attempt runs one full connection cycle and returns when it dies or the
// ctx is canceled. It classifies auth failures to escalate the backoff.
func (sv *Supervisor) attempt(ctx context.Context, m *managed, backoff *time.Duration) error {
	sess, err := session.New(m.cfg.Session)
	if err != nil {
		return err
	}
	sess.ServerAuth = m.cfg.Auth
	sv.mu.Lock()
	m.sess = sess
	sv.mu.Unlock()

	if err := sess.Start(ctx); err != nil {
		if isFatalAuth(err) {
			// Server refuses our credentials: escalate hard.
			*backoff = sv.opts.MaxBackoff
		}
		return err
	}

	// ONLINE: run stuck-watchdog while watching Done().
	sv.noteOnline(m.cfg.Session.ID)
	onlineSince := time.Now()
	done := sess.Done()
	watchdog := time.NewTicker(sv.opts.BaseBackoff)
	defer watchdog.Stop()
	for {
		select {
		case <-ctx.Done():
			sess.Stop(context.WithoutCancel(ctx))
			return nil
		case <-done:
			if time.Since(onlineSince) >= sv.opts.StableReset {
				*backoff = sv.opts.BaseBackoff // reset after stability
			}
			sv.noteOnline(m.cfg.Session.ID)
			return errors.New("connection dropped")
		case <-watchdog.C:
			if stuck := sv.stuckSince(sess); stuck > sv.opts.StuckThreshold {
				sv.opts.Logger.Warn("session stuck; forcing reconnect",
					"session", sess.Machine().State(), "dwell", stuck)
				sv.emitAction(ctx, m.cfg.Session.ID, "force-reconnect", string(sess.State()))
				sess.Stop(context.WithoutCancel(ctx))
				return errors.New("stuck state forced")
			}
		}
	}
}

func isFatalAuth(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sub := range []string{"server auth", "rejected handshake", "registration"} {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

func (sv *Supervisor) noteOnline(id string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.lastOnline[id] = time.Now()
}

// stuckSince reports how long the machine has dwelled in its current
// non-terminal transient state.
func (sv *Supervisor) stuckSince(sess *session.Session) time.Duration {
	h := sess.Machine().History()
	if len(h) == 0 {
		return 0
	}
	last := h[len(h)-1]
	switch last.To {
	case statemachine.Starting, statemachine.Connecting, statemachine.Authenticating, statemachine.Syncing:
		return time.Since(last.At)
	}
	return 0
}

func (sv *Supervisor) nextBackoff(cur time.Duration) time.Duration {
	next := time.Duration(math.Min(float64(cur*2), float64(sv.opts.MaxBackoff)))
	return next
}

func (sv *Supervisor) jittered(base time.Duration) time.Duration {
	f := rand.Float64()*2 - 1 // [-1,1)
	delta := float64(base) * sv.opts.Jitter * f
	return time.Duration(float64(base) + delta)
}

func (sv *Supervisor) emitAction(ctx context.Context, id, action, reason string) {
	if sv.opts.Bus == nil {
		return
	}
	_ = sv.opts.Bus.Publish(ctx, events.Event{
		Type: events.SupervisorAction, Session: id,
		Data: map[string]string{"action": action, "reason": reason},
	})
}

// Health reports per-session status.
func (sv *Supervisor) Health() map[string]Status {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	out := make(map[string]Status, len(sv.sessions))
	for id, m := range sv.sessions {
		st := Status{ID: id}
		if sv.phase[id] == "backoff" {
			st.State = statemachine.Reconnecting
		}
		if m.sess != nil {
			sess := m.sess
			if st.State == "" {
				st.State = sess.State()
			}
			st.Retries = sv.retries[id]
			st.LastOnline = sv.lastOnline[id]
			st.Creds = sess.Credentials()
		} else if st.State == "" {
			st.State = statemachine.Stopped
		}
		out[id] = st
	}
	return out
}

// Session returns the live session instance for raw operations (nil if
// unknown or not yet started). Protocol-level; SDK layers should prefer
// the api façade.
func (sv *Supervisor) Session(id string) *session.Session {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	if m, ok := sv.sessions[id]; ok {
		return m.sess
	}
	return nil
}

// Status is one session's supervisory view.
type Status struct {
	ID         string
	State      statemachine.State
	Retries    int
	LastOnline time.Time
	Creds      session.Credentials
}

// LoggerDebug is a tiny logging escape hatch for embedding layers.
func (sv *Supervisor) LoggerDebug(msg string, kv ...any) {
	sv.opts.Logger.Debug(msg, kv...)
}

// Sessions lists registered ids.
func (sv *Supervisor) Sessions() []string {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	out := make([]string, 0, len(sv.sessions))
	for id := range sv.sessions {
		out = append(out, id)
	}
	return out
}
