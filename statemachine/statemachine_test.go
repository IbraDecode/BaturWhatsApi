package statemachine

import (
	"testing"
	"time"
)

func TestLegalLifecycle(t *testing.T) {
	m := NewMachine()
	sequence := []State{Starting, Connecting, Authenticating, Syncing, Online,
		Reconnecting, Connecting, Authenticating, Online, Stopping, Stopped}
	for _, s := range sequence {
		if err := m.Move(s, "test"); err != nil {
			t.Fatalf("move to %s: %v", s, err)
		}
	}
	if m.State() != Stopped {
		t.Fatalf("final state %s", m.State())
	}
}

func TestIllegalTransitions(t *testing.T) {
	m := NewMachine()
	if err := m.Move(Online, "skip"); err == nil {
		t.Fatal("STOPPED->ONLINE must be illegal")
	}
	if err := m.Move(Connecting, "skip"); err == nil {
		t.Fatal("STOPPED->CONNECTING must be illegal (STARTING first)")
	}
	// Idempotent self-transition is allowed for recovery-code ergonomics.
	if err := m.Move(Stopped, "noop"); err != nil {
		t.Fatalf("self transition must be legal: %v", err)
	}
	for _, s := range []State{Starting, Connecting, Authenticating, Online} {
		_ = m.Move(s, "up")
	}
	if err := m.Move(Stopped, "yank"); err == nil {
		t.Fatal("ONLINE->STOPPED must go through STOPPING")
	}
}

func TestErrorAndDegradedPaths(t *testing.T) {
	m := NewMachine()
	for _, s := range []State{Starting, Connecting, Authenticating, Syncing, Online} {
		if err := m.Move(s, "up"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Move(Degraded, "ping lost"); err != nil {
		t.Fatal(err)
	}
	if err := m.Move(Online, "ping ok"); err != nil {
		t.Fatal(err)
	}
	if err := m.Move(Error, "boom"); err != nil {
		t.Fatal(err)
	}
	if err := m.Move(Reconnecting, "recover"); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionTableComplete(t *testing.T) {
	states := []State{Stopped, Starting, Connecting, Authenticating, Syncing,
		Online, Degraded, Reconnecting, Error, Stopping}
	for _, s := range states {
		if _, ok := table[s]; !ok {
			t.Fatalf("state %s missing from transition table", s)
		}
	}
	// Every state except STOPPED must reach Stopped via Stopping (recovery
	// and shutdown paths must always exist).
	for _, s := range states {
		if s == Stopped {
			continue
		}
		if !m2can(s, Stopping) {
			t.Fatalf("%s cannot go to STOPPING", s)
		}
	}
}

func m2can(from, to State) bool {
	if from == to {
		return true // no-op transitions are allowed
	}
	for _, cand := range table[from] {
		if cand == to {
			return true
		}
	}
	return false
}

func TestWatcher(t *testing.T) {
	m := NewMachine()
	w := m.Watch(8)
	defer w.Stop()
	go func() {
		_ = m.Move(Starting, "go")
	}()
	select {
	case tr := <-w.C():
		if tr.From != Stopped || tr.To != Starting {
			t.Fatalf("transition = %v", tr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher got nothing")
	}
}

func TestForceAndHistory(t *testing.T) {
	m := NewMachine()
	_ = m.Move(Online, "illegal?") // must fail
	m.Force(Online, "rescue")
	if m.State() != Online {
		t.Fatal("force failed")
	}
	h := m.History()
	last := h[len(h)-1]
	if last.Reason[0] != '!' {
		t.Fatalf("forced transition not marked: %v", last)
	}
}
