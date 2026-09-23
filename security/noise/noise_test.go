package noise

import (
	"bytes"
	"testing"
)

type pair struct {
	client, server         *XX
	clientSend, clientRecv *Cipher
	serverSend, serverRecv *Cipher
	remoteStaticClient     []byte
	remoteStaticServer     []byte
}

func doHandshake(t *testing.T, header []byte) *pair {
	t.Helper()
	clientStatic, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverStatic, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewXXClient(clientStatic, header)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewXXServer(serverStatic, header)
	if err != nil {
		t.Fatal(err)
	}
	p := &pair{client: c, server: s}

	ephC, err := c.ClientHello1()
	if err != nil {
		t.Fatal(err)
	}
	_ = ephC

	serverEph, staticCT, payloadCT, err := s.ServerHello1(c.eph.Public(), []byte("server-payload"))
	if err != nil {
		t.Fatal(err)
	}
	clientStaticCT, clientPayloadCT, err := c.ClientFinish(serverEph, staticCT, payloadCT, []byte("client-payload"))
	if err != nil {
		t.Fatal(err)
	}
	remoteStaticServer, _, err := s.AcceptFinish(clientStaticCT, clientPayloadCT)
	if err != nil {
		t.Fatal(err)
	}
	p.remoteStaticServer = remoteStaticServer
	p.remoteStaticClient = c.RemoteStatic()

	cs, cr, err := c.SendCipher()
	if err != nil {
		t.Fatal(err)
	}
	ss, sr, err := s.SendCipher()
	if err != nil {
		t.Fatal(err)
	}
	p.clientSend, p.clientRecv, p.serverSend, p.serverRecv = cs, cr, ss, sr
	return p
}

func TestHandshakeAndTransport(t *testing.T) {
	p := doHandshake(t, nil)
	if !bytes.Equal(p.remoteStaticClient, p.server.static.Public()) {
		t.Fatal("client learned wrong server static")
	}
	if !bytes.Equal(p.remoteStaticServer, p.client.static.Public()) {
		t.Fatal("server learned wrong client static")
	}
	// client -> server
	msg := []byte("hello server")
	ct := p.clientSend.Seal(nil, msg)
	pt, err := p.serverRecv.Open(nil, ct)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("c2s transport failed: %v", err)
	}
	// server -> client, counters advance independently per direction
	for i := 0; i < 100; i++ {
		m := []byte{byte(i)}
		c := p.serverSend.Seal(nil, m)
		got, err := p.clientRecv.Open(nil, c)
		if err != nil || !bytes.Equal(got, m) {
			t.Fatalf("s2c round %d failed: %v", i, err)
		}
	}
}

func TestHandshakeTamper(t *testing.T) {
	clientStatic, _ := NewKeyPair()
	serverStatic, _ := NewKeyPair()
	c, _ := NewXXClient(clientStatic, nil)
	s, _ := NewXXServer(serverStatic, nil)
	ephC, _ := c.ClientHello1()
	seph, sCT, _, _ := s.ServerHello1(ephC, nil)
	if _, _, err := c.ClientFinish(seph, sCT, []byte{0xFF, 0xFE}, nil); err == nil {
		t.Fatal("expected payload tamper to fail")
	}
}

func TestHeaderBinding(t *testing.T) {
	clientStatic, _ := NewKeyPair()
	serverStatic, _ := NewKeyPair()
	c, _ := NewXXClient(clientStatic, []byte("GET /stream"))
	s, _ := NewXXServer(serverStatic, []byte("GET /other"))
	ephC, _ := c.ClientHello1()
	seph, sCT, pCT, _ := s.ServerHello1(ephC, nil)
	if _, _, err := c.ClientFinish(seph, sCT, pCT, nil); err == nil {
		t.Fatal("different transport header must break handshake")
	}
}

func TestKeyPairPersistence(t *testing.T) {
	kp, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := KeyPairFromSeed(kp.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.Public(), restored.Public()) {
		t.Fatal("restored key mismatch")
	}
	if _, err := KeyPairFromSeed([]byte{1, 2, 3}); err == nil {
		t.Fatal("short seed must fail")
	}
}

func TestCounterMonotonic(t *testing.T) {
	p := doHandshake(t, nil)
	if p.clientSend.Counter() != 0 || p.serverRecv.Counter() != 0 {
		t.Fatal("counters must start at zero")
	}
	// Sequential frames must decrypt and advance counters.
	for i := 0; i < 5; i++ {
		m := []byte{byte(i)}
		ct := p.clientSend.Seal(nil, m)
		got, err := p.serverRecv.Open(nil, ct)
		if err != nil || !bytes.Equal(got, m) {
			t.Fatalf("frame %d failed: %v", i, err)
		}
	}
	// A forged frame is rejected and still consumes the expected nonce,
	// matching WhatsApp semantics where a failed open kills the stream.
	forged := p.clientSend.Seal(nil, []byte("z"))
	forged[0] ^= 0xFF
	if _, err := p.serverRecv.Open(nil, forged); err == nil {
		t.Fatal("forged frame accepted")
	}
	if _, err := p.serverRecv.Open(nil, forged); err == nil {
		t.Fatal("replayed frame accepted")
	}
}
