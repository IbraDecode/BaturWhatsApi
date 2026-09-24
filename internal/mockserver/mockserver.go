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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ibradecode/baturwhatsapi/internal/wapb"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/e2e"
	"github.com/ibradecode/baturwhatsapi/security/noise"
	"github.com/ibradecode/baturwhatsapi/security/wacert"
	"github.com/ibradecode/baturwhatsapi/transport"
)

// Server runs the mock control protocol.
type Server struct {
	Dict   *token.Dictionary
	Logger *slog.Logger

	mu         sync.Mutex
	registry   map[string]*Registration  // by device id
	devices    map[string]*deviceSession // by account JID
	e2eKeys    e2e.BobKeys
	e2eRatchet map[string]*e2e.Ratchet // per sender account
	e2eBundle  *e2e.PreKeyBundle
	static     *noise.KeyPair
	rootPriv   ed25519.PrivateKey
	certChain  []byte // signed by root -> intermediate -> leaf(static)
	// DropAfterRequests: after this many iq responses the server kills
	// the client connection (failure injection for supervisor tests).
	dropAfterRequests int
	// IgnoreAcks disables ping replies (network-stall simulation).
	IgnoreAcks bool
	// MediaDemo additionally pushes a media (image) message shortly after
	// connect, used to exercise attachment parsing end to end. Default
	// off so message-count-sensitive tests stay stable.
	MediaDemo bool
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
	srv := &Server{
		Dict:       dict,
		Logger:     slog.Default().With("comp", "mockserver"),
		registry:   map[string]*Registration{},
		devices:    map[string]*deviceSession{},
		e2eRatchet: map[string]*e2e.Ratchet{},
		static:     kp,
	}
	bk, _, err := e2e.NewBobKeys()
	if err != nil {
		return nil, err
	}
	srv.e2eKeys = bk
	bundle := e2e.BuildBundle(bk.Identity, bk.SignedPreKey, bk.SignedPreID,
		map[uint32][]byte{bk.OneTimeKeyID: bk.OneTimeKey.Public()})
	srv.e2eBundle = bundle
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	_ = rootPub
	if err != nil {
		return nil, err
	}
	interPub, interPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	leafDetails := wacert.BuildDetails(7, 3, kp.Public(), now.Add(-time.Hour), now.AddDate(1, 0, 0))
	interDetails := wacert.BuildDetails(3, 0, interPub, now.Add(-time.Hour), now.AddDate(2, 0, 0))
	leafSig := ed25519.Sign(interPriv, leafDetails)
	interSig := ed25519.Sign(rootPriv, interDetails)
	srv.certChain = wacert.BuildChain(leafDetails, leafSig, interDetails, interSig)
	srv.rootPriv = rootPriv
	return srv, nil
}

// E2EBundle publishes the server endpoint's X3DH bundle (demo recipient).
func (s *Server) E2EBundle() *e2e.PreKeyBundle { return s.e2eBundle }

// DeviceCount reports live sessions.
func (s *Server) DeviceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.devices)
}

// syncPage serves deterministic paged data for the sync engine tests:
// contacts (jid+name) and chats (jid+unread). cursor = start index.
func (s *Server) syncPage(iqID, stage, cursor string) binary.Node {
	const pageSize = 3
	start := 0
	if cursor != "" {
		fmt.Sscanf(cursor, "%d", &start)
	}
	total := 10
	if stage == "chats" {
		total = 7
	}
	var items []binary.Node
	next := start
	for i := 0; i < pageSize && next < total; i++ {
		if stage == "contacts" {
			items = append(items, binary.Node{Tag: "contact", Attrs: binary.Attrs{
				"jid":  fmt.Sprintf("628120000%03d@s.whatsapp.net", next),
				"name": fmt.Sprintf("Contact %d", next),
			}})
		} else {
			items = append(items, binary.Node{Tag: "chat", Attrs: binary.Attrs{
				"jid":    fmt.Sprintf("628120000%03d@s.whatsapp.net", next),
				"unread": fmt.Sprintf("%d", next%4),
			}})
		}
		next++
	}
	attrs := binary.Attrs{"id": iqID, "type": "result"}
	content := []binary.Node{{Tag: "sync", Attrs: binary.Attrs{"stage": stage}, Content: items}}
	if next < total {
		content[0].Attrs["cursor"] = fmt.Sprintf("%d", next)
	} else {
		content[0].Attrs["cursor"] = ""
	}
	return binary.Node{Tag: "iq", Attrs: attrs, Content: content}
}

func (s *Server) registerDevice(ds *deviceSession) {
	s.mu.Lock()
	s.devices[ds.reg.AccountJID] = ds
	s.mu.Unlock()
}

func (s *Server) unregisterDevice(account string, ds *deviceSession) {
	s.mu.Lock()
	if cur, ok := s.devices[account]; ok && cur == ds {
		delete(s.devices, account)
	}
	s.mu.Unlock()
}

func (s *Server) device(account string) *deviceSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devices[account]
}

// relayE2E decrypts an envelope from connOwner's session and delivers the
// plaintext to the target device as a server-pushed message.
func (s *Server) relayE2E(ctx context.Context, sender *deviceSession, n binary.Node) {
	child, ok := n.ChildByTag("e2e")
	if !ok {
		return
	}
	raw, ok := child.BytesContent()
	if !ok {
		return
	}
	env, err := e2e.ParseEnvelope(raw)
	if err != nil {
		s.Logger.Warn("e2e envelope parse", "err", err)
		return
	}
	s.mu.Lock()
	rt := s.e2eRatchet[sender.reg.AccountJID]
	s.mu.Unlock()
	var plain []byte
	if env.Type == e2e.EnvInit || rt == nil {
		rt, plain, err = e2e.BobSession(s.e2eKeys, env, e2e.ProtocolInfoV1)
		if err != nil {
			s.Logger.Warn("e2e init rejected", "err", err)
			return
		}
		s.mu.Lock()
		s.e2eRatchet[sender.reg.AccountJID] = rt
		s.mu.Unlock()
	} else {
		plain, err = rt.Decrypt(env)
		if err != nil {
			s.Logger.Warn("e2e decrypt", "err", err)
			return
		}
	}
	target := s.device(n.MustStringAttr("to"))
	if target == nil {
		s.Logger.Debug("e2e relay: unknown target")
		return
	}
	msg := binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id":   fmt.Sprintf("E2E%06d", time.Now().UnixNano()%1000000),
			"from": sender.reg.AccountJID,
			"to":   target.reg.AccountJID,
			"type": "text",
		},
		Content: []binary.Node{{Tag: "plain", Content: string(plain)}},
	}
	s.push(ctx, target, msg)
}

// RootPub returns the certificate trust root this mock server signed with.
func (s *Server) RootPub() ed25519.PublicKey { return s.rootPriv.Public().(ed25519.PublicKey) }

// SetDropAfterRequests makes the server sever the connection after every
// N-th incoming node from a device (<=0 disables). For chaos/recovery
// tests (drop counts any node: IQ, ping, …).
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
	serverEph, staticCT, certCT, err := xx.ServerHello1(ch.Ephemeral, s.certChain)
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
	s.registerDevice(sess)
	defer s.unregisterDevice(sess.reg.AccountJID, sess)
	s.Logger.Info("device online", "device", reg.DeviceID, "resumed", sess.resumed)

	return s.sessionLoop(ctx, sess)
}

type deviceSession struct {
	reg      Registration
	resumed  bool
	send     *noise.Cipher
	recv     *noise.Cipher
	mu       sync.Mutex
	writeMu  sync.Mutex
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
		if s.MediaDemo {
			time.Sleep(50 * time.Millisecond)
			s.pushMediaMessage(ctx, ds, "image", binary.Attrs{
				"url":      "https://mock.local/media/batur-demo.jpg",
				"mimetype": "image/jpeg",
				"caption":  "Batur demo snapshot",
				"width":    "640",
				"height":   "480",
			})
		}
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
	ds.mu.Lock()
	ds.reqCount++
	drop := s.dropAfterRequests > 0 && ds.reqCount%s.dropAfterRequests == 0
	ds.mu.Unlock()
	if drop && n.Tag != "xmlstreamend" {
		ds.conn.Close()
		return true
	}
	switch n.Tag {
	case "xmlstreamend":
		return true
	case "message":
		s.relayE2E(ctx, ds, n)
	case "a":
		if s.IgnoreAcks {
			return false
		}
		// ping -> ack via ib
		s.push(ctx, ds, binary.Node{
			Tag: "ib", Attrs: binary.Attrs{"from": ds.reg.AccountJID},
			Content: []binary.Node{{Tag: "ack", Attrs: n.Attrs}},
		})
	case "iq":
		id, _ := n.StringAttr("id")
		typ, _ := n.StringAttr("type")
		switch {
		case typ == "get" && n.MustStringAttr("xmlns") == "batur.demo":
			var echo []binary.Node
			for _, c := range n.Children() {
				if c.Tag == "echo" {
					echo = append(echo, binary.Node{Tag: "echo",
						Attrs: binary.Attrs{"msg": c.MustStringAttr("msg")}})
				}
			}
			s.push(ctx, ds, binary.Node{
				Tag: "iq", Attrs: binary.Attrs{"id": id, "type": "result"},
				Content: echo,
			})
		case typ == "get" && n.MustStringAttr("xmlns") == "batur.sync":
			s.push(ctx, ds, s.syncPage(id, n.MustStringAttr("stage"),
				n.MustStringAttr("cursor")))
		case typ == "get" && n.MustStringAttr("xmlns") == "batur.pair":
			s.pairDevice(ctx, ds, id, n)
		default: // connect config iq and everything else -> result
			resp := binary.Node{
				Tag: "iq",
				Attrs: binary.Attrs{
					"id": id, "type": "result",
					"account": ds.reg.AccountJID,
				},
			}
			s.push(ctx, ds, resp)
		}
	}
	return false
}

// pairDevice answers a companion pairing IQ: first a QR challenge, then
// pair-success carrying the account already assigned at handshake.
// This is the mock companion flow (T-103), not live WhatsApp registration.
func (s *Server) pairDevice(ctx context.Context, ds *deviceSession, id string, n binary.Node) {
	child, _ := n.ChildByTag("pair-device")
	deviceID := child.MustStringAttr("device_id")
	if deviceID == "" {
		deviceID = ds.reg.DeviceID
	}
	exp := time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)
	s.push(ctx, ds, binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"id": id, "type": "result"},
		Content: []binary.Node{{
			Tag: "pair-device",
			Attrs: binary.Attrs{
				"code":       "2@" + deviceID + "," + ds.reg.AccountJID,
				"ref":        "ref-" + deviceID,
				"expires_at": exp,
			},
		}},
	})
	s.push(ctx, ds, binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"id": id, "type": "result"},
		Content: []binary.Node{{
			Tag: "pair-success",
			Attrs: binary.Attrs{
				"account_jid":    ds.reg.AccountJID,
				"device_id":      deviceID,
				"server_static":  base64.StdEncoding.EncodeToString(s.static.Public()),
				"cert_chain":     base64.StdEncoding.EncodeToString(s.certChain),
				"reg_id":         "1",
				"expires_at":     exp,
			},
		}},
	})
}

func (s *Server) pushMessage(ctx context.Context, ds *deviceSession, text string) {
	msg := binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"from": ds.reg.AccountJID,
			"id":   fmt.Sprintf("MOCK%06d", time.Now().UnixNano()%1000000),
			"type": "text",
		},
		Content: []binary.Node{{Tag: "plain", Content: text}},
	}
	s.push(ctx, ds, msg)
}

// pushMediaMessage sends a legacy-XML media message (e.g. <image/> with url,
// mime, caption, size attrs — the same child-tag scheme <plain> uses for
// text in the mock wire format).
func (s *Server) pushMediaMessage(ctx context.Context, ds *deviceSession, kind string, attrs binary.Attrs) {
	msg := binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"from": ds.reg.AccountJID,
			"id":   fmt.Sprintf("MOCK%06d", time.Now().UnixNano()%1000000),
			"type": kind,
		},
		Content: []binary.Node{{Tag: kind, Attrs: attrs}},
	}
	s.push(ctx, ds, msg)
}

func (s *Server) push(ctx context.Context, ds *deviceSession, n binary.Node) {
	plain := binary.MarshalDict(n, s.Dict)
	ds.writeMu.Lock()
	defer ds.writeMu.Unlock()
	ct := ds.send.Seal(nil, plain)
	_ = ds.conn.SendBinary(ctx, ct)
}

func recvTimeout(ctx context.Context, conn transport.Conn, d time.Duration) ([]byte, error) {
	if d <= 0 {
		return conn.ReceiveBinary(ctx)
	}
	tctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return conn.ReceiveBinary(tctx)
}
