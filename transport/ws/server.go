// Minimal WebSocket server used only by tests and the embedded demo server.
// It is intentionally small: fixed single client, unmasked server frames,
// no permessage-deflate. Production deployments terminate WSS upstream;
// this exists so the client implementation can be verified over a real TCP
// socket in CI without external services.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Upgrade accepts an HTTP/1.1 upgrade request as a WebSocket server
// connection. It hijacks the net.Conn and returns a server-mode Conn that
// reads masked client frames and writes unmasked frames. This lets the API
// server host real WebSocket event streams without external libraries.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		return nil, errors.New("ws: not an upgrade request")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("ws: hijack unsupported")
	}
	nc, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	if err := nc.SetDeadline(time.Time{}); err != nil {
		nc.Close()
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		nc.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		nc.Close()
		return nil, err
	}
	c := newConn(nc, brw.Reader, nil, false)
	go c.readLoop()
	return c, nil
}

// ServerConn is an accepted test server connection.
type ServerConn struct {
	nc   net.Conn
	br   *bufio.Reader
	once sync.Once
}

// ServeWS completes the handshake on an accepted TCP connection. rw holds
// the buffered reader that already consumed the request.
func ServeWS(rw *bufio.ReadWriter, nc net.Conn, req *http.Request) (*ServerConn, error) {
	key := req.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") || key == "" {
		return nil, errors.New("ws: not an upgrade request")
	}
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		return nil, err
	}
	return &ServerConn{nc: nc, br: rw.Reader}, nil
}

// ReadRequest parses the opening HTTP request from the buffered reader.
func ReadRequest(rw *bufio.ReadWriter) (*http.Request, error) {
	return http.ReadRequest(rw.Reader)
}

// NewReadWriter wraps a raw conn with test-server buffers.
func NewReadWriter(nc net.Conn) *bufio.ReadWriter {
	return bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
}

// Recv reads one client frame (unwrapping its mask).
func (s *ServerConn) Recv() (opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(s.br, hdr[:]); err != nil {
		return
	}
	opcode = hdr[0] & 0x0F
	if hdr[1]&0x80 == 0 {
		err = fmt.Errorf("%w: client frames must be masked", ErrProtocol)
		return
	}
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(s.br, b[:]); err != nil {
			return
		}
		length = uint64(b[0])<<8 | uint64(b[1])
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(s.br, b[:]); err != nil {
			return
		}
		length = 0
		for _, v := range b {
			length = length<<8 | uint64(v)
		}
	}
	if length > MaxFrameSize {
		err = ErrFrameTooLarge
		return
	}
	key := make([]byte, 4)
	if _, err = io.ReadFull(s.br, key); err != nil {
		return
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(s.br, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= key[i%4]
	}
	return
}

// SendRaw writes an unmasked server frame (for tests: ping, fragments, etc).
func (s *ServerConn) SendRaw(fin bool, opcode byte, payload []byte) error {
	var hdr []byte
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	hdr = append(hdr, b0)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	_, err := s.nc.Write(append(hdr, payload...))
	return err
}

// Close tears down the server side.
func (s *ServerConn) Close() error {
	var err error
	s.once.Do(func() { err = s.nc.Close() })
	return err
}
