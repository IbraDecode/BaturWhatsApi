// Package ws implements a dependency-free WebSocket implementation for
// BaturWhatsApi: a client (RFC 6455) for engine transports, a test server,
// and an Upgrade path used by the API server's real-time event bridge.
//
// Scope: binary/text data frames with continuation handling, control frames
// (ping/pong/close), masked client frames, size limits against memory
// exhaustion. Extensions and subprotocol negotiation beyond "binary" are out
// of scope for the engine's needs.
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Frame size ceiling: WhatsApp frames never approach this; it exists to
// fail fast on hostile streams instead of growing memory.
const MaxFrameSize = 16 << 20

// Dial errors.
var (
	ErrHandshakeRejected = errors.New("ws: handshake rejected")
	ErrFrameTooLarge     = errors.New("ws: frame too large")
	ErrProtocol          = errors.New("ws: protocol violation")
	ErrClosed            = errors.New("ws: connection closed")
)

// Options configures Dialer.
type Options struct {
	Header    http.Header
	TLSConfig *tls.Config
	// HandshakeTimeout caps the opening handshake (default 30s).
	HandshakeTimeout time.Duration
}

type Dialer struct {
	Options Options
}

// NewDialer creates a WebSocket dialer.
func NewDialer(opts Options) *Dialer {
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 30 * time.Second
	}
	return &Dialer{Options: opts}
}

var wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func acceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Dial connects to a ws:// or wss:// URL and performs the opening
// handshake. The returned Conn satisfies transport.Conn (adapted by
// transport/ws glue elsewhere; here we return the concrete type plus a
// BindingHeader for the noise channel binding).
func (d *Dialer) Dial(ctx context.Context, rawURL string) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ws: parse url: %w", err)
	}
	var hostPort string
	var conn net.Conn
	dialer := &net.Dialer{}
	switch u.Scheme {
	case "ws":
		hostPort = u.Host
		if !strings.Contains(hostPort, ":") {
			hostPort += ":80"
		}
		conn, err = dialer.DialContext(ctx, "tcp", hostPort)
	case "wss":
		hostPort = u.Host
		if !strings.Contains(hostPort, ":") {
			hostPort += ":443"
		}
		tlsCfg := d.Options.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		tlsD := &tls.Dialer{Config: tlsCfg}
		conn, err = tlsD.DialContext(ctx, "tcp", hostPort)
	default:
		return nil, fmt.Errorf("ws: unsupported scheme %q", u.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("ws: dial: %w", err)
	}

	// Opening handshake.
	deadline := time.Now().Add(d.Options.HandshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, err
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)
	reqPath := u.RequestURI()
	host := u.Host
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n", reqPath, host)
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", wsKey)
	for k, vs := range d.Options.Header {
		for _, v := range vs {
			fmt.Fprintf(&req, "%s: %s\r\n", k, v)
		}
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws: send request: %w", err)
	}
	// Parse the opening handshake response through the SAME buffered
	// reader that frame parsing will use later. (http.ReadResponse would
	// layer a second buffer and steal frame bytes.)
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ws: read status line: %w", err)
	}
	parts := strings.Split(strings.TrimSpace(statusLine), " ")
	if len(parts) < 2 || parts[1] != "101" {
		conn.Close()
		return nil, fmt.Errorf("%w: %q", ErrHandshakeRejected, strings.TrimSpace(statusLine))
	}
	var upgrade, accept string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("ws: read headers: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upgrade":
			upgrade = v
		case "sec-websocket-accept":
			accept = v
		}
	}
	if !strings.EqualFold(upgrade, "websocket") || accept != acceptKey(wsKey) {
		conn.Close()
		return nil, fmt.Errorf("%w: bad upgrade response", ErrHandshakeRejected)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	// Binding header: the exact request line + response status the peer
	// saw; both ends reconstruct the same byte string for noise binding.
	binding := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", reqPath, host, strings.TrimSpace(statusLine)))
	c := newConn(conn, br, binding, true)
	go c.readLoop()
	return c, nil
}

// Conn is a WebSocket binary connection.
type Conn struct {
	nc       net.Conn
	br       *bufio.Reader
	writeMu  sync.Mutex
	masked   bool
	partial  []byte
	closeMu  sync.Mutex
	isClosed bool
	closeCh  chan struct{}
	frames   chan []byte
	errMu    sync.Mutex
	lastErr  error
	header   []byte
}

func newConn(nc net.Conn, br *bufio.Reader, binding []byte, clientSide bool) *Conn {
	c := &Conn{
		nc:      nc,
		br:      br,
		masked:  clientSide,
		closeCh: make(chan struct{}),
		frames:  make(chan []byte, 64),
		header:  binding,
	}
	return c
}

// BindingHeader returns the channel-binding bytes for the noise handshake.
func (c *Conn) BindingHeader() []byte { return c.header }

// SendBinary writes a single binary frame (masked for clients).
func (c *Conn) SendBinary(ctx context.Context, payload []byte) error {
	return c.writeFrame(ctx, 0x2, payload)
}

// SendText writes a single text frame.
func (c *Conn) SendText(ctx context.Context, payload []byte) error {
	return c.writeFrame(ctx, 0x1, payload)
}

// SendPing emits a ping frame (server keep-alive or client liveness).
func (c *Conn) SendPing(ctx context.Context, payload []byte) error {
	return c.writeFrame(ctx, 0x9, payload)
}

// writeFrame emits one FIN-only data/control frame.
func (c *Conn) writeFrame(ctx context.Context, opcode byte, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		c.nc.SetWriteDeadline(dl)
		defer c.nc.SetWriteDeadline(time.Time{})
	}
	header := []byte{0x80 | opcode}
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if c.masked {
		header[1] |= 0x80
		key := make([]byte, 4)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		header = append(header, key...)
		body := make([]byte, n)
		for i := 0; i < n; i++ {
			body[i] = payload[i] ^ key[i%4]
		}
		if _, err := c.nc.Write(append(header, body...)); err != nil {
			return c.fail(err)
		}
		return nil
	}
	if _, err := c.nc.Write(append(header, payload...)); err != nil {
		return c.fail(err)
	}
	return nil
}

// ReceiveBinary waits for the next data frame.
func (c *Conn) ReceiveBinary(ctx context.Context) ([]byte, error) {
	select {
	case f := <-c.frames:
		return f, nil
	case <-c.closeCh:
		select {
		case f := <-c.frames:
			return f, nil
		default:
			return nil, c.failure()
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Conn) Close() error {
	c.closeMu.Lock()
	already := c.isClosed
	c.closeMu.Unlock()
	if !already {
		c.sendCloseBestEffort()
	}
	return c.shutdown(nil)
}

// shutdown is a reentrancy-safe once-close: it never calls back into
// writeFrame from inside the close path.
func (c *Conn) shutdown(reason error) error {
	c.closeMu.Lock()
	if c.isClosed {
		c.closeMu.Unlock()
		return nil
	}
	c.isClosed = true
	if reason != nil {
		c.errMu.Lock()
		if c.lastErr == nil {
			c.lastErr = reason
		}
		c.errMu.Unlock()
	}
	close(c.closeCh)
	c.closeMu.Unlock()
	return c.nc.Close()
}

// sendClose tries to emit a close frame before tearing the socket down;
// failures here are best-effort.
func (c *Conn) sendCloseBestEffort() {
	_ = c.writeFrameNoFail(context.Background(), 0x8, []byte{0x03, 0xE8})
}

func (c *Conn) writeFrameNoFail(ctx context.Context, opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	header := []byte{0x80 | opcode, byte(len(payload))}
	if c.masked {
		header[1] |= 0x80
		key := make([]byte, 4)
		header = append(header, key...)
		body := make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ key[i%4]
		}
		_, err := c.nc.Write(append(header, body...))
		return err
	}
	_, err := c.nc.Write(append(header, payload...))
	return err
}

func (c *Conn) fail(err error) error {
	c.errMu.Lock()
	if c.lastErr == nil {
		c.lastErr = err
	}
	c.errMu.Unlock()
	c.shutdown(nil)
	return err
}

func (c *Conn) failure() error {
	c.errMu.Lock()
	err := c.lastErr
	c.errMu.Unlock()
	if err != nil {
		return err
	}
	return ErrClosed
}

// readLoop parses frames and routes data frames to c.frames.
func (c *Conn) readLoop() {
	for {
		frame, err := c.readFrame()
		if err != nil {
			c.fail(err)
			return
		}
		switch frame.opcode {
		case 0x8: // close
			c.fail(ErrClosed)
			return
		case 0x9: // ping -> pong
			if err := c.writePong(frame.payload); err != nil {
				c.fail(err)
				return
			}
		case 0xA: // pong
		case 0x0, 0x1, 0x2: // continuation / text / binary
			msg, ok := c.accumulate(frame)
			if !ok {
				c.fail(ErrProtocol)
				return
			}
			if msg != nil {
				select {
				case c.frames <- msg:
				case <-c.closeCh:
					return
				}
			}
		default:
			c.fail(fmt.Errorf("%w: opcode %d", ErrProtocol, frame.opcode))
			return
		}
	}
}

// accumulate merges fragmented data frames.
func (c *Conn) accumulate(f frame) ([]byte, bool) {
	if f.opcode != 0x0 { // not a continuation: start (or standalone)
		if !f.fin {
			c.partial = append([]byte{}, f.payload...)
			return nil, true
		}
		return f.payload, true
	}
	// continuation frame
	if len(c.partial) == 0 {
		return nil, false // unsolicited continuation
	}
	c.partial = append(c.partial, f.payload...)
	if !f.fin {
		return nil, true
	}
	out := c.partial
	c.partial = nil
	return out, true
}

type frame struct {
	fin     bool
	opcode  byte
	payload []byte
}

func (c *Conn) readFrame() (frame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return frame{}, err
	}
	f := frame{fin: hdr[0]&0x80 != 0, opcode: hdr[0] & 0x0F}
	masked := hdr[1]&0x80 != 0
	if c.masked {
		// client mode: a server must not mask frames to us
		if masked {
			return frame{}, fmt.Errorf("%w: masked server frame", ErrProtocol)
		}
	} else if !masked {
		// server mode: clients must mask their frames
		return frame{}, fmt.Errorf("%w: unmasked client frame", ErrProtocol)
	}
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return frame{}, err
		}
		length = uint64(b[0])<<8 | uint64(b[1])
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return frame{}, err
		}
		length = 0
		for _, v := range b {
			length = length<<8 | uint64(v)
		}
	}
	if length > MaxFrameSize {
		return frame{}, ErrFrameTooLarge
	}
	var key [4]byte
	if !c.masked {
		// server mode: the 4-byte masking key precedes the payload
		if _, err := io.ReadFull(c.br, key[:]); err != nil {
			return frame{}, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return frame{}, err
	}
	if !c.masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	f.payload = payload
	return f, nil
}

func (c *Conn) writePong(payload []byte) error {
	return c.writeFrame(context.Background(), 0xA, payload)
}
