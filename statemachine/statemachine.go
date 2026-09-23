// Package statemachine implements the explicit connection lifecycle used by
// every BaturWhatsApi session. All transitions are validated against the
// transition table, observable through subscribers and testable in isolation.
package statemachine

import (
	"fmt"
	"sync"
	"time"
)

// State is a connection lifecycle state.
type State string

// Engine states.
const (
	Stopped         State = "STOPPED"
	Starting        State = "STARTING"
	Connecting      State = "CONNECTING"
	Authenticating  State = "AUTHENTICATING"
	Syncing         State = "SYNCING"
	Online          State = "ONLINE"
	Degraded        State = "DEGRADED"
	Reconnecting    State = "RECONNECTING"
	Error           State = "ERROR"
	Stopping        State = "STOPPING"
)

// Transition describes a state change with context for observability.
type Transition struct {
	From    State
	To      State
	Reason  string
	At      time.Time
}

// String renders the transition for logs.
func (t Transition) String() string {
	return fmt.Sprintf("%s->%s(%s)", t.From, t.To, t.Reason)
}

// legal transitions from each state.
var table = map[State][]State{
	Stopped:        {Starting, Stopping},
	Starting:       {Connecting, Stopping, Error},
	Connecting:     {Authenticating, Reconnecting, Stopping, Error},
	Authenticating: {Syncing, Online, Reconnecting, Stopping, Error},
	Syncing:        {Online, Degraded, Reconnecting, Stopping, Error},
	Online:         {Degraded, Reconnecting, Syncing, Stopping, Error},
	Degraded:       {Online, Reconnecting, Syncing, Stopping, Error},
	Reconnecting:   {Connecting, Authenticating, Stopping, Error},
	Error:          {Reconnecting, Starting, Stopping, Stopped},
	Stopping:       {Stopped},
}

// ErrTransition is returned for illegal state changes.
type ErrTransition struct {
	From, To State
}

func (e ErrTransition) Error() string {
	return fmt.Sprintf("statemachine: illegal transition %s -> %s", e.From, e.To)
}

// Machine is a thread-safe FSM with an observer channel.
type Machine struct {
	mu       sync.Mutex
	state    State
	history  []Transition
	maxHist  int
	watchers []chan Transition
}

// NewMachine starts in STOPPED.
func NewMachine() *Machine {
	return &Machine{state: Stopped, maxHist: 64}
}

// State returns the current state.
func (m *Machine) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Can reports whether a transition is legal.
func (m *Machine) Can(to State) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.canLocked(to)
}

func (m *Machine) canLocked(to State) bool {
	if to == m.state {
		return true
	}
	for _, s := range table[m.state] {
		if s == to {
			return true
		}
	}
	return false
}

// Move performs a validated transition.
func (m *Machine) Move(to State, reason string) error {
	m.mu.Lock()
	if !m.canLocked(to) {
		from := m.state
		m.mu.Unlock()
		return ErrTransition{From: from, To: to}
	}
	tr, ok := m.applyLocked(to, reason, false)
	watchers := append([]chan Transition{}, m.watchers...)
	m.mu.Unlock()
	if ok {
		notifyWatchers(watchers, tr)
	}
	return nil
}

// applyLocked records the transition; caller holds mu.
func (m *Machine) applyLocked(to State, reason string, forced bool) (Transition, bool) {
	from := m.state
	if from == to {
		return Transition{}, false
	}
	m.state = to
	tr := Transition{From: from, To: to, Reason: reason, At: time.Now().UTC()}
	if forced {
		tr.Reason = "!" + reason
	}
	m.history = append(m.history, tr)
	if len(m.history) > m.maxHist {
		m.history = m.history[len(m.history)-m.maxHist:]
	}
	return tr, true
}

func notifyWatchers(watchers []chan Transition, tr Transition) {
	for _, w := range watchers {
		select {
		case w <- tr:
		default:
		}
	}
}

// Force jumps to a state bypassing validation (emergency recovery path;
// recorded in history with an "!" prefixed reason).
func (m *Machine) Force(to State, reason string) {
	m.mu.Lock()
	tr, ok := m.applyLocked(to, reason, true)
	watchers := append([]chan Transition{}, m.watchers...)
	m.mu.Unlock()
	if ok {
		notifyWatchers(watchers, tr)
	}
}



// Watch returns a buffered channel of transitions. Call Stop to unsubscribe.
func (m *Machine) Watch(buffer int) *Watcher {
	if buffer < 1 {
		buffer = 1
	}
	ch := make(chan Transition, buffer)
	m.mu.Lock()
	m.watchers = append(m.watchers, ch)
	m.mu.Unlock()
	return &Watcher{m: m, ch: ch}
}

// History returns a copy of recent transitions (oldest first).
func (m *Machine) History() []Transition {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Transition{}, m.history...)
}

// Watcher is an observer subscription.
type Watcher struct {
	m  *Machine
	ch chan Transition
}

// C is the event channel.
func (w *Watcher) C() <-chan Transition { return w.ch }

// Stop unsubscribes.
func (w *Watcher) Stop() {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	for i, cand := range w.m.watchers {
		if cand == w.ch {
			w.m.watchers = append(w.m.watchers[:i], w.m.watchers[i+1:]...)
			break
		}
	}
}

// Active reports whether the state machine is in a live (non-stopped) phase.
func Active(s State) bool {
	switch s {
	case Connecting, Authenticating, Syncing, Online, Degraded, Reconnecting:
		return true
	}
	return false
}
