// Package sync implements BaturWhatsApi's resumable synchronization
// framework: ordered stages, cursor checkpoints persisted through the
// engine's storage layer, and sync lifecycle events on the bus.
//
// The framework is protocol-agnostic; the concrete page fetchers live
// next to the session/protocol code and plug in as StageFuncs.
package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/storage"
)

// Errors.
var (
	ErrNoStore = errors.New("sync: storage required")
)

// Checkpoint is the durable sync position for one stage.
type Checkpoint struct {
	Stage     string    `json:"stage"`
	Cursor    string    `json:"cursor"`
	Items     uint64    `json:"items"`
	Complete  bool      `json:"complete"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Page is one fetch result.
type Page struct {
	Items  []any  // decoded domain items (opaque to the framework)
	Cursor string // empty => stage finished
}

// StageFunc fetches the page after cursor. The raw payload may be any
// protocol value; the fetcher decodes it into domain items.
type StageFunc func(ctx context.Context, cursor string) (Page, error)

// Stage is a named, resumable sync step.
type Stage struct {
	Name  string
	Fetch StageFunc
}

// Runner drives stages for one session.
type Runner struct {
	Session string
	Store   storage.KV
	Bus     *events.Bus
	Stages  []Stage
	// ForceRestart ignores stored checkpoints.
	ForceRestart bool
}

func (r *Runner) key(stage string) string {
	return "session/" + r.Session + "/sync/" + stage
}

// LoadCheckpoint reads the persisted position (ErrNotFound => fresh).
func (r *Runner) LoadCheckpoint(ctx context.Context, stage string) (Checkpoint, error) {
	if r.Store == nil {
		return Checkpoint{}, ErrNoStore
	}
	raw, err := r.Store.Get(ctx, r.key(stage))
	if err != nil {
		return Checkpoint{}, err
	}
	var cp Checkpoint
	err = json.Unmarshal(raw, &cp)
	return cp, err
}

func (r *Runner) saveCheckpoint(ctx context.Context, cp Checkpoint) error {
	cp.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	return r.Store.Set(ctx, r.key(cp.Stage), raw)
}

// Run executes all stages in order, resuming each from its checkpoint.
// On the first failure it emits sync.failed and returns; completed
// stages keep their checkpoints.
func (r *Runner) Run(ctx context.Context) error {
	r.emit(ctx, events.SyncStarted, map[string]any{"session": r.Session, "stages": r.stageNames()})
	for _, st := range r.Stages {
		cp, err := r.LoadCheckpoint(ctx, st.Name)
		switch {
		case r.ForceRestart:
			cp = Checkpoint{Stage: st.Name}
		case errors.Is(err, storage.ErrNotFound):
			cp = Checkpoint{Stage: st.Name}
		case err != nil:
			r.fail(ctx, st.Name, err)
			return err
		case cp.Complete:
			continue
		}
		cursor := cp.Cursor
		for {
			page, err := st.Fetch(ctx, cursor)
			if err != nil {
				r.fail(ctx, st.Name, err)
				return fmt.Errorf("sync %s: %w", st.Name, err)
			}
			cp.Items += uint64(len(page.Items))
			cp.Cursor = page.Cursor
			if err := r.saveCheckpoint(ctx, cp); err != nil {
				r.fail(ctx, st.Name, err)
				return err
			}
			if page.Cursor == "" {
				cp.Complete = true
				cp.Cursor = ""
				if err := r.saveCheckpoint(ctx, cp); err != nil {
					return err
				}
				break
			}
			cursor = page.Cursor
		}
	}
	r.emit(ctx, events.SyncCompleted, map[string]any{"session": r.Session})
	return nil
}

// Reset clears checkpoints (next Run starts fresh).
func (r *Runner) Reset(ctx context.Context) error {
	keys, err := r.Store.List(ctx, "session/"+r.Session+"/sync/")
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := r.Store.Delete(ctx, k); err != nil {
			return err
		}
	}
	return nil
}

// Progress reports checkpoints (observability).
func (r *Runner) Progress(ctx context.Context) []Checkpoint {
	keys, err := r.Store.List(ctx, "session/"+r.Session+"/sync/")
	if err != nil {
		return nil
	}
	out := make([]Checkpoint, 0, len(keys))
	for _, k := range keys {
		raw, err := r.Store.Get(ctx, k)
		if err != nil {
			continue
		}
		var cp Checkpoint
		if json.Unmarshal(raw, &cp) == nil {
			out = append(out, cp)
		}
	}
	return out
}

func (r *Runner) fail(ctx context.Context, stage string, err error) {
	r.emit(ctx, events.SyncFailed, map[string]any{"session": r.Session, "stage": stage, "err": err.Error()})
}

func (r *Runner) emit(ctx context.Context, typ string, data any) {
	if r.Bus != nil {
		_ = r.Bus.Publish(ctx, events.Event{Type: typ, Session: r.Session, Data: data})
	}
}

func (r *Runner) stageNames() []string {
	out := make([]string, len(r.Stages))
	for i, s := range r.Stages {
		out[i] = s.Name
	}
	return out
}
