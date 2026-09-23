// Package events implements BaturWhatsApi's internal event bus.
//
// Guarantees:
//   - Per-subscription ordering: a subscriber sees events in publish order.
//   - Slow handler isolation: every subscriber has its own queue and worker
//     goroutine; a slow consumer never blocks publishers or other consumers
//     beyond its queue capacity.
//   - Backpressure policy: when a queue is full the publisher blocks until
//     the context expires, or the oldest event is dropped (per-subscription
//     policy), with drops counted for observability.
//   - Handler panic recovery: a panicking handler is isolated, counted and
//     reported through the bus stats without killing dispatch.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Canonical event type names emitted by the engine.
const (
	ConnectionState  = "connection.state"
	ConnectionError  = "connection.error"
	SessionReady     = "session.ready"
	SessionError     = "session.error"
	MessageReceived  = "message.received"
	MessageSent      = "message.sent"
	MessageUpdated   = "message.updated"
	MessageAck       = "message.acknowledged"
	ChatUpdated      = "chat.updated"
	ContactUpdated   = "contact.updated"
	GroupUpdated     = "group.updated"
	SyncStarted      = "sync.started"
	SyncCompleted    = "sync.completed"
	SyncFailed       = "sync.failed"
	MediaUploaded    = "media.uploaded"
	MediaFailed      = "media.failed"
	SupervisorAction = "supervisor.action"
)

// Event is a single bus message. Data holds a typed payload owned by the
// producer (handlers must treat it as read-only).
type Event struct {
	Seq     uint64
	Type    string
	Session string
	Time    time.Time
	Data    any
}

// Handler consumes events. It receives a context tied to bus shutdown.
type Handler func(context.Context, Event)

// QueuePolicy decides what happens when a subscriber queue is full.
type QueuePolicy int

const (
	// PolicyBlock waits for space (publisher backpressure, ordered).
	PolicyBlock QueuePolicy = iota
	// PolicyDropOldest discards the oldest queued event to stay live.
	PolicyDropOldest
)

// ErrClosed is returned when publishing to a closed bus.
var ErrClosed = errors.New("events: bus closed")

type subscription struct {
	id      uint64
	match   string // exact type or "prefix.*" or "*"
	prefix  string
	exact   string
	queue   chan Event
	policy  QueuePolicy
	handler Handler
	cancel  context.CancelFunc
}

// Subscription handle returned by Subscribe.
type Subscription struct {
	bus *Bus
	sub *subscription
}

// Unsubscribe stops delivery and drains remaining events.
func (s *Subscription) Unsubscribe() {
	s.bus.remove(s.sub)
}

// Stats reports bus health.
type Stats struct {
	Published   uint64
	Delivered   uint64
	Dropped     uint64
	Panics      uint64
	Subscribers int
}

// Bus is the event dispatcher.
type Bus struct {
	mu      sync.RWMutex
	subs    map[uint64]*subscription
	nextID  uint64
	closed  bool
	done    chan struct{}
	seq     atomic.Uint64
	pubCnt  atomic.Uint64
	delCnt  atomic.Uint64
	dropCnt atomic.Uint64
	panics  atomic.Uint64

	// OnDrop and OnPanic allow the observability layer to tap failures.
	OnDrop  func(subID uint64, ev Event)
	OnPanic func(subID uint64, recovered any)
}

// New builds a bus.
func New() *Bus {
	return &Bus{subs: map[uint64]*subscription{}, done: make(chan struct{})}
}

// Subscribe registers a handler for event types matching pattern:
// an exact name ("connection.state"), a family prefix ("connection.*")
// or "*" for everything. bufferSize < 1 is clamped to 1.
func (b *Bus) Subscribe(pattern string, bufferSize int, policy QueuePolicy, h Handler) (*Subscription, error) {
	if h == nil {
		return nil, errors.New("events: nil handler")
	}
	if pattern == "" {
		return nil, errors.New("events: empty pattern")
	}
	if bufferSize < 1 {
		bufferSize = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	b.nextID++
	ctx, cancel := context.WithCancel(context.Background())
	sub := &subscription{
		id:      b.nextID,
		match:   pattern,
		policy:  policy,
		handler: h,
		cancel:  cancel,
	}
	switch {
	case pattern == "*":
	case strings.HasSuffix(pattern, ".*"):
		sub.prefix = strings.TrimSuffix(pattern, ".*")
	default:
		sub.exact = pattern
	}
	sub.queue = make(chan Event, bufferSize)
	b.subs[sub.id] = sub
	go b.runSubscriber(ctx, sub)
	return &Subscription{bus: b, sub: sub}, nil
}

// MustSubscribe panics on error (for static wiring).
func (b *Bus) MustSubscribe(pattern string, bufferSize int, policy QueuePolicy, h Handler) *Subscription {
	s, err := b.Subscribe(pattern, bufferSize, policy, h)
	if err != nil {
		panic(err)
	}
	return s
}

func (sub *subscription) matches(evType string) bool {
	if sub.match == "*" {
		return true
	}
	if sub.prefix != "" {
		return strings.HasPrefix(evType, sub.prefix+".")
	}
	return evType == sub.exact
}

func (b *Bus) runSubscriber(ctx context.Context, sub *subscription) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.queue:
			if !ok {
				return
			}
			b.invoke(sub, ev)
		}
	}
}

func (b *Bus) invoke(sub *subscription, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			b.panics.Add(1)
			if b.OnPanic != nil {
				b.OnPanic(sub.id, r)
			}
		}
	}()
	sub.handler(context.Background(), ev)
}

func (b *Bus) remove(sub *subscription) {
	b.mu.Lock()
	delete(b.subs, sub.id)
	b.mu.Unlock()
	sub.cancel()
}

// Publish delivers an event to all matching subscribers.
func (b *Bus) Publish(ctx context.Context, ev Event) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrClosed
	}
	targets := make([]*subscription, 0, len(b.subs))
	for _, s := range b.subs {
		if s.matches(ev.Type) {
			targets = append(targets, s)
		}
	}
	b.mu.RUnlock()

	ev.Seq = b.seq.Add(1)
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	b.pubCnt.Add(1)

	for _, s := range targets {
		switch s.policy {
		case PolicyDropOldest:
			select {
			case s.queue <- ev:
			default:
				// Make room, then enqueue.
				select {
				case dropped := <-s.queue:
					b.dropCnt.Add(1)
					if b.OnDrop != nil {
						b.OnDrop(s.id, dropped)
					}
				default:
				}
				select {
				case s.queue <- ev:
				case <-ctx.Done():
					return ctx.Err()
				case <-b.done:
					return ErrClosed
				}
			}
		default: // PolicyBlock
			select {
			case s.queue <- ev:
			case <-ctx.Done():
				return ctx.Err()
			case <-b.done:
				return ErrClosed
			}
		}
		b.delCnt.Add(1)
	}
	return nil
}

// Close stops dispatch; already queued events may or may not be delivered.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	subs := make([]*subscription, 0, len(b.subs))
	for _, s := range b.subs {
		subs = append(subs, s)
	}
	b.subs = map[uint64]*subscription{}
	b.mu.Unlock()
	close(b.done)
	for _, s := range subs {
		s.cancel()
	}
}

// Stats returns current counters.
func (b *Bus) Stats() Stats {
	b.mu.RLock()
	n := len(b.subs)
	b.mu.RUnlock()
	return Stats{
		Published:   b.pubCnt.Load(),
		Delivered:   b.delCnt.Load(),
		Dropped:     b.dropCnt.Load(),
		Panics:      b.panics.Load(),
		Subscribers: n,
	}
}

// LastSeq reports the highest published sequence for diagnostics.
func (b *Bus) LastSeq() uint64 { return b.seq.Load() }

func (s Stats) String() string {
	return fmt.Sprintf("events: published=%d delivered=%d dropped=%d panics=%d subs=%d",
		s.Published, s.Delivered, s.Dropped, s.Panics, s.Subscribers)
}
