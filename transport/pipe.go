package transport

import (
	"context"
	"sync"
	"sync/atomic"
)

// Pipe returns two connected in-memory conns (client side and server side),
// used by the engine's protocol-level test servers and unit tests. Frames
// are bounded queues; writes apply backpressure via ctx cancellation.
//
// Close semantics: closing either end marks both endpoints closed; buffered
// frames remain readable until drained, after which readers see ErrClosed
// and senders fail immediately.
func Pipe(header []byte) (client, server Conn) {
	a := &pipeEnd{header: header, recv: make(chan []byte, 64)}
	b := &pipeEnd{header: header, recv: make(chan []byte, 64)}
	a.peer, b.peer = b, a
	st := &shared{done: make(chan struct{})}
	a.state, b.state = st, st
	return a, b
}

// shared holds cross-endpoint liveness so Close on either side is visible
// to both without lock-ordering hazards.
type shared struct {
	closed atomic.Bool
	done   chan struct{} // closed once when either end calls Close
	once   sync.Once
}

type pipeEnd struct {
	peer   *pipeEnd
	state  *shared
	header []byte
	recv   chan []byte
}

func (p *pipeEnd) sendable() bool {
	return !p.state.closed.Load()
}

func (p *pipeEnd) SendBinary(ctx context.Context, frame []byte) error {
	if !p.sendable() {
		return ErrClosed
	}
	buf := make([]byte, len(frame))
	copy(buf, frame)
	select {
	case p.peer.recv <- buf:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.state.done:
		return ErrClosed
	}
}

func (p *pipeEnd) SendText(ctx context.Context, text []byte) error {
	return p.SendBinary(ctx, text)
}

func (p *pipeEnd) ReceiveBinary(ctx context.Context) ([]byte, error) {
	select {
	case f := <-p.recv:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.state.done:
		select {
		case f := <-p.recv:
			return f, nil
		default:
			return nil, ErrClosed
		}
	}
}

func (p *pipeEnd) BindingHeader() []byte { return p.header }

func (p *pipeEnd) Close() error {
	p.state.once.Do(func() {
		p.state.closed.Store(true)
		close(p.state.done)
	})
	return nil
}

var _ Conn = (*pipeEnd)(nil)
