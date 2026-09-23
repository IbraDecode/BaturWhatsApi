package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/version"
	"github.com/ibradecode/baturwhatsapi/transport/ws"
)

// wsConnections is the live WebSocket subscriber gauge (rendered in /metrics).
var wsConnections atomic.Int64

// wsCommand is a client -> server command frame (JSON text).
type wsCommand struct {
	Op      string `json:"op"` // ping|send|sync|subscribe
	Session string `json:"session,omitempty"`
	To      string `json:"to,omitempty"`
	Text    string `json:"text,omitempty"`
	JID     string `json:"jid,omitempty"` // subscribe: filter to one chat
}

// wsEnvelope is a server -> client frame.
type wsEnvelope struct {
	Type    string `json:"type"` // hello|pong|result|error|event
	Op      string `json:"op,omitempty"`
	Ok      bool   `json:"ok,omitempty"`
	ID      string `json:"id,omitempty"`
	Session string `json:"session,omitempty"`
	Error   string `json:"error,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// wsEventBridge multiplexes live engine events over a WebSocket and accepts
// a small command set (send, sync, subscribe). It reuses the same JSON
// serialization as the SSE endpoint so wire payloads stay consistent.
type wsEventBridge struct {
	conn     *ws.Conn
	batur    *api.Batur
	close    chan struct{}
	once     sync.Once
	filterMu sync.RWMutex
	session  string // non-empty = forward only one session's events
}

// hSessionWS upgrades /v1/ws and runs the bridge until the peer disconnects.
func (s *Server) hSessionWS(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "websocket: "+err.Error())
		return
	}
	wsConnections.Add(1)
	defer wsConnections.Add(-1)

	b := &wsEventBridge{conn: conn, batur: s.Batur, close: make(chan struct{})}
	hello := wsEnvelope{Type: "hello", Data: map[string]any{"engine": "baturwhatsapi", "version": version.Version}}
	if err := b.send(hello); err != nil {
		_ = conn.Close()
		return
	}
	done := make(chan struct{})
	go func() { b.stream(); close(done) }()
	b.loop()
	b.closeOnce()
	<-done
	_ = conn.Close()
}

func (b *wsEventBridge) send(v wsEnvelope) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.conn.SendText(context.Background(), raw)
}

// loop reads command frames until the connection dies.
func (b *wsEventBridge) loop() {
	for {
		raw, err := b.conn.ReceiveBinary(context.Background())
		if err != nil {
			return
		}
		var cmd wsCommand
		if json.Unmarshal(raw, &cmd) != nil || cmd.Op == "" {
			_ = b.send(wsEnvelope{Type: "error", Error: "bad command frame"})
			continue
		}
		switch cmd.Op {
		case "ping":
			_ = b.send(wsEnvelope{Type: "pong"})
		case "send":
			rep := wsEnvelope{Type: "result", Op: "send"}
			if cmd.Session == "" || cmd.To == "" {
				rep.Error = "session and to required"
				rep.Ok = false
			} else {
				id, err := b.batur.SendText(context.Background(), cmd.Session,
					api.Target{JID: cmd.To}, cmd.Text)
				rep.Ok = err == nil
				rep.ID = id
				if err != nil {
					rep.Error = err.Error()
				}
			}
			_ = b.send(rep)
		case "sync":
			rep := wsEnvelope{Type: "result", Op: "sync"}
			if err := b.batur.RunSync(context.Background(), cmd.Session); err != nil {
				rep.Error = err.Error()
			} else {
				rep.Ok = true
			}
			_ = b.send(rep)
		case "subscribe":
			b.filterMu.Lock()
			b.session = cmd.Session
			b.filterMu.Unlock()
			_ = b.send(wsEnvelope{Type: "result", Op: "subscribe", Ok: true, Session: cmd.Session})
		default:
			_ = b.send(wsEnvelope{Type: "error", Error: "unknown op " + cmd.Op})
		}
	}
}

// stream forwards bus events the client is subscribed to, with periodic WS
// pings to keep intermediaries and the peer awake.
func (b *wsEventBridge) stream() {
	ch := make(chan events.Event, 256)
	handle, err := b.batur.Bus().Subscribe("*", 256, events.PolicyDropOldest,
		func(_ context.Context, ev events.Event) {
			select {
			case ch <- ev:
			default:
			}
		})
	if err != nil {
		b.closeOnce()
		return
	}
	defer handle.Unsubscribe()
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.close:
			return
		case <-ticker.C:
			_ = b.conn.SendPing(context.Background(), nil)
		case ev := <-ch:
			if !b.wants(ev) {
				continue
			}
			raw, err := json.Marshal(map[string]any{
				"seq": ev.Seq, "type": ev.Type, "session": ev.Session,
				"time": ev.Time, "data": publicData(ev),
			})
			if err != nil {
				continue
			}
			if err := b.conn.SendText(context.Background(), raw); err != nil {
				return
			}
		}
	}
}

func (b *wsEventBridge) wants(ev events.Event) bool {
	b.filterMu.RLock()
	defer b.filterMu.RUnlock()
	return b.session == "" || ev.Session == b.session
}

func (b *wsEventBridge) closeOnce() {
	b.once.Do(func() { close(b.close) })
}
