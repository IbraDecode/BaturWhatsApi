package ws

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"
)

func startServer(t *testing.T, handler func(*ServerConn) error) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				brw := NewReadWriter(c)
				req, err := ReadRequest(brw)
				if err != nil {
					return
				}
				sc, err := ServeWS(brw, c, req)
				if err != nil {
					return
				}
				_ = handler(sc)
				// Graceful drain: like a real peer, keep the socket until
				// the client closes it (prevents write-after-close RST
				// data loss in loopback tests).
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				for {
					if _, _, err := sc.Recv(); err != nil {
						break
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func dialClient(t *testing.T, addr string) *Conn {
	t.Helper()
	d := NewDialer(Options{HandshakeTimeout: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.Dial(ctx, "ws://"+addr+"/stream")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestHandshakeAndFrames(t *testing.T) {
	done := make(chan struct{})
	addr := startServer(t, func(sc *ServerConn) error {
		defer close(done)
		opcode, payload, err := sc.Recv()
		if err != nil {
			t.Errorf("server recv: %v", err)
			return err
		}
		if opcode != 0x2 || string(payload) != "hello" {
			t.Errorf("server got opcode=%d payload=%q", opcode, payload)
		}
		return sc.SendRaw(true, 0x2, []byte("world"))
	})
	c := dialClient(t, addr)
	ctx := context.Background()
	if err := c.SendBinary(ctx, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReceiveBinary(ctx)
	if err != nil || string(got) != "world" {
		t.Fatalf("client got %q %v", got, err)
	}
	<-done
}

func TestLargeFramesAllLengthForms(t *testing.T) {
	sizes := []int{5, 125, 126, 65535, 65536, 70000}
	addr := startServer(t, func(sc *ServerConn) error {
		for {
			_, payload, err := sc.Recv()
			if err != nil {
				return err
			}
			// Echo back the same size.
			if err := sc.SendRaw(true, 0x2, payload); err != nil {
				return err
			}
		}
	})
	c := dialClient(t, addr)
	ctx := context.Background()
	for _, n := range sizes {
		want := make([]byte, n)
		if _, err := rand.Read(want); err != nil {
			t.Fatal(err)
		}
		if err := c.SendBinary(ctx, want); err != nil {
			t.Fatalf("send %d: %v", n, err)
		}
		got, err := c.ReceiveBinary(ctx)
		if err != nil {
			t.Fatalf("recv %d: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("echo mismatch at size %d", n)
		}
	}
}

func TestFragmentedServerMessage(t *testing.T) {
	addr := startServer(t, func(sc *ServerConn) error {
		_, _, err := sc.Recv()
		if err != nil {
			return err
		}
		if err := sc.SendRaw(false, 0x2, []byte("frag-")); err != nil {
			return err
		}
		if err := sc.SendRaw(false, 0x0, []byte("mented-")); err != nil {
			return err
		}
		return sc.SendRaw(true, 0x0, []byte("message"))
	})
	c := dialClient(t, addr)
	ctx := context.Background()
	if err := c.SendBinary(ctx, []byte("go")); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReceiveBinary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "frag-mented-message" {
		t.Fatalf("got %q", got)
	}
}

func TestPingPong(t *testing.T) {
	pongCh := make(chan []byte, 1)
	addr := startServer(t, func(sc *ServerConn) error {
		// Send ping, then wait for client's pong.
		if err := sc.SendRaw(true, 0x9, []byte("are you there")); err != nil {
			return err
		}
		for {
			opcode, payload, err := sc.Recv()
			if err != nil {
				return err
			}
			if opcode == 0xA {
				select {
				case pongCh <- payload:
				default:
				}
				return sc.SendRaw(true, 0x2, []byte("ok"))
			}
		}
	})
	c := dialClient(t, addr)
	got, err := c.ReceiveBinary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case pong := <-pongCh:
		if string(pong) != "are you there" {
			t.Fatalf("pong payload = %q", pong)
		}
	default:
		t.Fatal("client never ponged")
	}
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestRejectNonWebSocketUpgrade(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		conn.Close()
	}()
	d := NewDialer(Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = d.Dial(ctx, "ws://"+ln.Addr().String()+"/")
	if err == nil || !strings.Contains(err.Error(), "handshake rejected") {
		t.Fatalf("expected rejection, got %v", err)
	}
}

func TestBindingHeaderNonNil(t *testing.T) {
	addr := startServer(t, func(sc *ServerConn) error {
		_, _, err := sc.Recv()
		return err
	})
	c := dialClient(t, addr)
	if len(c.BindingHeader()) == 0 {
		t.Fatal("binding header must be set for noise channel binding")
	}
}
