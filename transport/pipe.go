package transport

import (
	"context"
	"sync"
)

// Pipe returns two connected in-memory conns (client side and server side),
// used by the engine's protocol-level test servers and unit tests. Frames
// are bounded queues; writes apply backpressure via ctx cancellation.
func Pipe(header []byte) (client, server Conn) {
	a := newPipeEnd(header)
	b := newPipeEnd(header)
	a.peer, b.peer = b, a
	return a, b
}

type pipeEnd struct {
	peer   *pipeEnd
	header []byte

	mu     sync.Mutex
	closed bool
	recv   chan []byte
	done   chan struct{}
}

func newPipeEnd(header []byte) *pipeEnd {
	return &pipeEnd{header: header, recv: make(chan []byte, 64), done: make(chan struct{})}
}

func (p *pipeEnd) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *pipeEnd) SendBinary(ctx context.Context, frame []byte) error {
	peer := p.peer
	if p.isClosed() || peer.isClosed() {
		return ErrClosed
	}
	buf := make([]byte, len(frame))
	copy(buf, frame)
	select {
	case peer.recv <- buf:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-peer.done:
		return ErrClosed
	case <-p.done:
		return ErrClosed
	}
}

func (p *pipeEnd) ReceiveBinary(ctx context.Context) ([]byte, error) {
	select {
	case f, ok := <-p.recv:
		if !ok {
			return nil, ErrClosed
		}
		return f, nil
	case <-p.done:
		// Drain any frames already queued before reporting closure.
		select {
		case f, ok := <-p.recv:
			if ok {
				return f, nil
			}
		default:
		}
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pipeEnd) BindingHeader() []byte { return p.header }

func (p *pipeEnd) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	p.mu.Unlock()
	// Propagate: the peer can no longer receive new sends and must see
	// EOF once its queue drains.
	if peer := p.peer; peer != nil {
		peer.mu.Lock()
		if !peer.closed {
			peer.closed = true
			close(peer.done)
		}
		peer.mu.Unlock()
	}
	return nil
}

var _ Conn = (*pipeEnd)(nil)
