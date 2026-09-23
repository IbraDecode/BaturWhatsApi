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
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/transport/ws"
)

// wsConnections is the live WebSocket subscriber gauge (rendered in /metrics).
var wsConnections atomic.Int64

// wsPingsTotal counts keepalive pings sent by the WS bridge.
var wsPingsTotal atomic.Uint64

// wsCommand is a client -> server command frame (JSON text).
type wsCommand struct {
	Op      string `json:"op"` // ping|send|sync|subscribe|unsubscribe
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
	enabled  bool          // start disabled until the client opts in via subscribe
	session  string        // non-empty = forward only one session's events
	chat     string        // non-empty = forward only messages to/from this chat
	ping     time.Duration // keepalive interval; 0 = default 25s
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

	b := &wsEventBridge{conn: conn, batur: s.Batur, close: make(chan struct{}), ping: s.WSPingInterval}
	s.trackConn(conn)
	defer s.untrackConn(conn)
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
			b.enabled = true
			b.session = cmd.Session
			b.chat = cmd.JID
			b.filterMu.Unlock()
			_ = b.send(wsEnvelope{Type: "result", Op: "subscribe", Ok: true, Session: cmd.Session, ID: cmd.JID})
		case "unsubscribe":
			b.filterMu.Lock()
			b.enabled = false
			b.session = ""
			b.chat = ""
			b.filterMu.Unlock()
			_ = b.send(wsEnvelope{Type: "result", Op: "unsubscribe", Ok: true})
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
	interval := b.ping
	if interval <= 0 {
		interval = 25 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-b.close:
			return
		case <-ticker.C:
			wsPingsTotal.Add(1)
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
	if !b.enabled {
		return false
	}
	if b.session != "" && ev.Session != b.session {
		return false
	}
	if b.chat != "" && evChat(ev) != b.chat {
		return false
	}
	return true
}

// evChat extracts the chat/peer JID an event concerns.
func evChat(ev events.Event) string {
	switch d := ev.Data.(type) {
	case binary.Node:
		if c, ok := d.StringAttr("from"); ok {
			return c
		}
		if c, ok := d.StringAttr("to"); ok {
			return c
		}
	case api.Message:
		return d.Chat.JID
	}
	return ""
}

func (b *wsEventBridge) closeOnce() {
	b.once.Do(func() { close(b.close) })
}
