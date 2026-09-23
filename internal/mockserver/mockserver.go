// Package mockserver implements a protocol-level WhatsApp-web-style server
// used for integration tests and the local demo mode. It speaks the exact
// same wire protocol as the engine (noise XX + binary nodes over frames),
// which exercises every layer end to end without external services.
//
// It is NOT a reimplementation of WhatsApp's proprietary registration:
// pairing here is "first contact registers, known noise keys resume".
package mockserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ibradecode/baturwhatsapi/internal/wapb"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/noise"
	"github.com/ibradecode/baturwhatsapi/transport"
)

// Server runs the mock control protocol.
type Server struct {
	Dict   *token.Dictionary
	Logger *slog.Logger

	mu       sync.Mutex
	registry map[string]*Registration // by device id
	static   *noise.KeyPair
	// DropAfterRequests: after this many iq responses the server kills
	// the client connection (failure injection for supervisor tests).
	dropAfterRequests int
	// IgnoreAcks disables ping replies (network-stall simulation).
	IgnoreAcks bool
}

// Registration is what the mock "accounts DB" remembers per device.
type Registration struct {
	DeviceID   string `json:"device_id"`
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	NoisePub   string `json:"noise_pub"`
	AccountJID string `json:"account"`
}

// New builds a mock server.
func New(dict *token.Dictionary) (*Server, error) {
	kp, err := noise.NewKeyPair()
	if err != nil {
		return nil, err
	}
	if dict == nil {
		dict = token.Default()
	}
	return &Server{
		Dict:     dict,
		Logger:   slog.Default().With("comp", "mockserver"),
		registry: map[string]*Registration{},
		static:   kp,
	}, nil
}

// SetDropAfterRequests makes the server sever the connection after every
// N-th IQ response for a device (<=0 disables). For chaos/recovery tests.
func (s *Server) SetDropAfterRequests(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropAfterRequests = n
}

// Registrations returns a snapshot of paired devices.
func (s *Server) Registrations() map[string]Registration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Registration, len(s.registry))
	for k, v := range s.registry {
		out[k] = *v
	}
	return out
}

// Dialer adapts the mock server to transport.Dialer over in-memory pipes.
type Dialer struct {
	Srv *Server
}

// Dial implements transport.Dialer.
func (d Dialer) Dial(ctx context.Context, url string) (transport.Conn, error) {
	client, server := transport.Pipe([]byte("batur-mock-binding"))
	sctx := context.WithoutCancel(ctx)
	go func() {
		if err := d.Srv.ServeConn(sctx, server); err != nil {
			d.Srv.Logger.Debug("serve conn ended", "err", err)
		}
	}()
	return client, nil
}

// ServeConn runs the full mock lifecycle over one conn.
func (s *Server) ServeConn(ctx context.Context, conn transport.Conn) error {
	defer conn.Close()

	xx, err := noise.NewXXServer(s.static, conn.BindingHeader())
	if err != nil {
		return err
	}
	// ClientHello.
	frame, err := recvTimeout(ctx, conn, 10*time.Second)
	if err != nil {
		return fmt.Errorf("mock: client hello: %w", err)
	}
	chMsg, err := wapb.UnwrapTop(frame, wapb.HSFieldClientHello)
	if err != nil || chMsg == nil {
		return errors.New("mock: bad client hello")
	}
	ch, err := wapb.ParseClientHello(chMsg)
	if err != nil || len(ch.Ephemeral) != 32 {
		return errors.New("mock: malformed client hello")
	}
	cert := []byte("mock-cert:" + time.Now().UTC().Format(time.RFC3339))
	serverEph, staticCT, certCT, err := xx.ServerHello1(ch.Ephemeral, cert)
	if err != nil {
		return err
	}
	sh := wapb.WrapTop(wapb.HSFieldServerHello,
		(&wapb.ServerHello{Ephemeral: serverEph, Static: staticCT, Payload: certCT}).Build())
	if err := conn.SendBinary(ctx, sh); err != nil {
		return err
	}
	// ClientFinish.
	frame, err = recvTimeout(ctx, conn, 10*time.Second)
	if err != nil {
		return fmt.Errorf("mock: client finish: %w", err)
	}
	cfMsg, err := wapb.UnwrapTop(frame, wapb.HSFieldClientFinish)
	if err != nil || cfMsg == nil {
		return errors.New("mock: bad client finish")
	}
	cf, err := wapb.ParseClientFinish(cfMsg)
	if err != nil {
		return err
	}
	remoteStatic, payload, err := xx.AcceptFinish(cf.Static, cf.Payload)
	if err != nil {
		return fmt.Errorf("mock: finish rejected: %w", err)
	}
	send, recv, err := xx.SendCipher()
	if err != nil {
		return err
	}
	var reg Registration
	if err := json.Unmarshal(payload, &reg); err != nil {
		return fmt.Errorf("mock: bad registration: %w", err)
	}
	sess, err := s.register(reg, remoteStatic)
	if err != nil {
		return err
	}
	sess.send, sess.recv, sess.conn = send, recv, conn
	s.Logger.Info("device online", "device", reg.DeviceID, "resumed", sess.resumed)

	return s.sessionLoop(ctx, sess)
}

type deviceSession struct {
	reg      Registration
	resumed  bool
	send     *noise.Cipher
	recv     *noise.Cipher
	mu       sync.Mutex
	conn     transport.Conn
	reqCount int
}

func (s *Server) register(reg Registration, remoteStatic []byte) (*deviceSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.registry[reg.DeviceID]
	if reg.AccountJID == "" {
		reg.AccountJID = fmt.Sprintf("62%09d@s.whatsapp.net",
			len(s.registry)+1001)
	}
	s.registry[reg.DeviceID] = &reg
	return &deviceSession{reg: reg, resumed: existed}, nil
}

// sessionLoop: decrypted node dispatch.
func (s *Server) sessionLoop(ctx context.Context, ds *deviceSession) error {
	conn, recv := ds.conn, ds.recv
	// Schedule one proactive demo message right after connect.
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.pushMessage(ctx, ds, "Hello from Batur mock server")
	}()
	for {
		raw, err := recvTimeout(ctx, conn, 0)
		if err != nil {
			return err
		}
		plain, err := recv.Open(nil, raw)
		if err != nil {
			return fmt.Errorf("mock: decrypt failed (bad cipher state or tamper): %w", err)
		}
		node, err := binary.Decode(s.Dict, plain)
		if err != nil {
			s.Logger.Warn("mock: undecodable node", "err", err)
			continue
		}
		if quit := s.handle(ctx, ds, node); quit {
			return nil
		}
	}
}

func (s *Server) handle(ctx context.Context, ds *deviceSession, n binary.Node) bool {
	conn, send := ds.conn, ds.send
	switch n.Tag {
	case "xmlstreamend":
		return true
	case "a":
		if s.IgnoreAcks {
			return false
		}
		// ping -> ack via ib
		s.push(ctx, conn, send, binary.Node{
			Tag: "ib", Attrs: binary.Attrs{"from": ds.reg.AccountJID},
			Content: []binary.Node{{Tag: "ack", Attrs: n.Attrs}},
		})
	case "iq":
		id, _ := n.StringAttr("id")
		typ, _ := n.StringAttr("type")
		ds.mu.Lock()
		ds.reqCount++
		drop := s.dropAfterRequests > 0 && ds.reqCount%s.dropAfterRequests == 0
		ds.mu.Unlock()
		switch {
		case drop:
			conn.Close()
			return true
		case typ == "get" && n.MustStringAttr("xmlns") == "batur.demo":
			var echo []binary.Node
			for _, c := range n.Children() {
				if c.Tag == "echo" {
					echo = append(echo, binary.Node{Tag: "echo",
						Attrs: binary.Attrs{"msg": c.MustStringAttr("msg")}})
				}
			}
			s.push(ctx, conn, send, binary.Node{
				Tag: "iq", Attrs: binary.Attrs{"id": id, "type": "result"},
				Content: echo,
			})
		default: // connect config iq and everything else -> result
			resp := binary.Node{
				Tag: "iq",
				Attrs: binary.Attrs{
					"id": id, "type": "result",
					"account": ds.reg.AccountJID,
				},
			}
			s.push(ctx, conn, send, resp)
		}
	}
	return false
}

func (s *Server) pushMessage(ctx context.Context, ds *deviceSession, text string) {
	conn, send := ds.conn, ds.send
	msg := binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"from": ds.reg.AccountJID,
			"id":   fmt.Sprintf("MOCK%06d", time.Now().UnixNano()%1000000),
			"type": "text",
		},
		Content: []binary.Node{{Tag: "plain", Content: text}},
	}
	s.push(ctx, conn, send, msg)
}

func (s *Server) push(ctx context.Context, conn transport.Conn, send *noise.Cipher, n binary.Node) {
	ds := send
	plain := binary.MarshalDict(n, s.Dict)
	ct := ds.Seal(nil, plain)
	_ = conn.SendBinary(ctx, ct)
}

func recvTimeout(ctx context.Context, conn transport.Conn, d time.Duration) ([]byte, error) {
	if d <= 0 {
		return conn.ReceiveBinary(ctx)
	}
	tctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return conn.ReceiveBinary(tctx)
}
