// Package apiserver exposes the core engine over HTTP (REST + SSE).
//
// The core NEVER depends on this package — it is one consumer of the api
// façade among several (SDKs, WebSocket). Endpoints are versioned under
// /v1. Bearer-token auth via BATUR_API_TOKEN (fail-closed: if unset the
// server binds to localhost only and refuses to start publicly).
package apiserver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/version"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/transport/ws"
)

// ErrNoToken means public binding was requested without an API token.
var ErrNoToken = errors.New("apiserver: BATUR_API_TOKEN required for non-local bind")

// Server wraps an api.Batur instance with HTTP endpoints.
type Server struct {
	Batur          *api.Batur
	Bind           string        // ":8080" etc
	Token          string        // bearer token; empty = require localhost bind
	EventQueue     int           // per-subscriber queue (default 256)
	MaxBodyBytes   int64         // cap POST request body size; 0 = default 1 MiB
	ReadTimeout    time.Duration // HTTP ReadTimeout; 0 = default 15s
	WSPingInterval time.Duration // WS bridge keepalive ping; 0 = default 25s

	srv     *http.Server
	testURL string // set by tests when routed through httptest

	connMu sync.Mutex
	conns  map[*ws.Conn]struct{} // hijacked WS conns, force-closed on shutdown
}

// New validates config and wires the handler.
func New(s *Server) (*Server, error) {
	if s.Batur == nil {
		return nil, errors.New("apiserver: nil Batur")
	}
	localhostOnly := s.Bind == "" ||
		strings.HasPrefix(s.Bind, "127.0.0.1:") ||
		strings.HasPrefix(s.Bind, "localhost:")
	if s.Token == "" && !localhostOnly {
		return nil, ErrNoToken
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.hHealth)
	mux.HandleFunc("GET /v1/sessions", s.hSessions)
	mux.HandleFunc("GET /v1/sessions/{id}", s.hSessionGet)
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.hSessionDelete)
	mux.HandleFunc("POST /v1/sessions/{id}/iq", s.hSessionIQ)
	mux.HandleFunc("POST /v1/sessions/{id}/text", s.hSessionText)
	mux.HandleFunc("GET /v1/events", s.hEvents)
	mux.HandleFunc("GET /v1/ws", s.hSessionWS)
	mux.HandleFunc("GET /metrics", s.hMetrics)
	mux.HandleFunc("POST /v1/sessions/{id}/sync", s.hSessionSync)
	mux.HandleFunc("GET /v1/sessions/{id}/contacts", s.hSessionContacts)
	mux.HandleFunc("GET /v1/sessions/{id}/chats", s.hSessionChats)
	mux.HandleFunc("GET /v1/sessions/{id}/history", s.hSessionHistory)
	mux.HandleFunc("GET /v1/sessions/{id}/history/{msgID}", s.hSessionHistoryOne)
	s.srv = &http.Server{
		Addr:         s.Bind,
		Handler:      s.logRequests(s.auth(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE: managed per-stream
	}
	if s.ReadTimeout > 0 {
		s.srv.ReadTimeout = s.ReadTimeout
	}
	s.conns = make(map[*ws.Conn]struct{})
	return s, nil
}

func (s *Server) trackConn(c *ws.Conn) {
	s.connMu.Lock()
	s.conns[c] = struct{}{}
	s.connMu.Unlock()
}

func (s *Server) untrackConn(c *ws.Conn) {
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
}

// closeConnections force-closes any hijacked WS connections. http.Server
// opts out of managing hijacked conns, so without this graceful shutdown
// would strand bridge goroutines blocked on reads.
func (s *Server) closeConnections() {
	s.connMu.Lock()
	cs := make([]*ws.Conn, 0, len(s.conns))
	for c := range s.conns {
		cs = append(cs, c)
	}
	s.conns = make(map[*ws.Conn]struct{})
	s.connMu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

// logRequests wraps an http.Handler and emits one structured slog line
// per request (method, path, status, latency, bytes). Health is skipped
// to keep the noise floor down.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"latency_ms", time.Since(start).Milliseconds(),
			"bytes", rec.bytes,
		)
	})
}

// statusRecorder wraps http.ResponseWriter to capture the response status
// code and total bytes written for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(c int) {
	s.status = c
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = 200
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush delegates to the embedded ResponseWriter so SSE / WS upgrade
// handlers, which type-assert http.Flusher, keep working through the
// recording wrapper.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the embedded ResponseWriter so ws.Upgrade, which
// type-asserts http.Hijacker, still works through the recording wrapper.
// The status/byte accounting stops at that point.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("apiserver: underlying ResponseWriter is not an http.Hijacker")
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		if s.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			want := sha256.Sum256([]byte(s.Token))
			gotH := sha256.Sum256([]byte(got))
			if subtle.ConstantTimeCompare(gotH[:], want[:]) != 1 {
				writeErr(w, http.StatusUnauthorized, "bad token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// bodyLimit returns the configured POST body cap (default 1 MiB).
func (s *Server) bodyLimit() int64 {
	if s.MaxBodyBytes > 0 {
		return s.MaxBodyBytes
	}
	return 1 << 20
}

// ListenAndServe starts the server (blocks until ctx cancels).
func (s *Server) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := s.srv.Shutdown(sctx)
		s.closeConnections()
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{
		"error": msg,
		"code":  httpCodeName(code),
	})
}

// httpCodeName returns a stable, programmatic-friendly token for an
// HTTP status (e.g. "not_found", "unauthorized", "bad_request"). Stable
// across versions so clients can switch on it instead of parsing the
// English message.
func httpCodeName(code int) string {
	switch code {
	case 400:
		return "bad_request"
	case 401:
		return "unauthorized"
	case 403:
		return "forbidden"
	case 404:
		return "not_found"
	case 405:
		return "method_not_allowed"
	case 408:
		return "request_timeout"
	case 413:
		return "body_too_large"
	case 415:
		return "unsupported_media_type"
	case 429:
		return "too_many_requests"
	case 500:
		return "internal"
	case 502:
		return "bad_gateway"
	case 503:
		return "unavailable"
	case 504:
		return "gateway_timeout"
	default:
		if code >= 400 && code < 500 {
			return "client_error"
		}
		if code >= 500 {
			return "server_error"
		}
		return "ok"
	}
}

func (s *Server) hHealth(w http.ResponseWriter, r *http.Request) {
	st := s.Batur.Bus().Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"engine":  "BaturWhatsApi",
		"version": version.Version,
		"uptime":  "ok",
		"events":  st,
		"now":     time.Now().UTC(),
	})
}

func (s *Server) hSessions(w http.ResponseWriter, r *http.Request) {
	out := []api.SessionStatus{}
	for _, id := range s.Batur.Sessions() {
		if st, err := s.Batur.Status(id); err == nil {
			out = append(out, st)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) hSessionGet(w http.ResponseWriter, r *http.Request) {
	st, err := s.Batur.Status(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) hSessionDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Batur.Detach(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type iqRequest struct {
	Tag     string            `json:"tag"`
	Attrs   map[string]any    `json:"attrs"`
	Content []json.RawMessage `json:"content,omitempty"`
	Timeout string            `json:"timeout,omitempty"`
}

type nodeJSON struct {
	Tag     string          `json:"tag"`
	Attrs   map[string]any  `json:"attrs,omitempty"`
	Content json.RawMessage `json:"content,omitempty"`
}

func (s *Server) hSessionIQ(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, s.bodyLimit())
	var req iqRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad request json")
		return
	}
	if req.Tag == "" {
		writeErr(w, http.StatusBadRequest, "tag required")
		return
	}
	node := binary.Node{Tag: req.Tag, Attrs: binary.Attrs{}}
	for k, v := range req.Attrs {
		node.Attrs[k] = v
	}
	for _, c := range req.Content {
		var n binary.Node
		if err := json.Unmarshal(c, &n); err != nil {
			writeErr(w, http.StatusBadRequest, "bad content node: "+err.Error())
			return
		}
		kids, _ := node.Content.([]binary.Node)
		node.Content = append(kids, n)
	}
	ctx := r.Context()
	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad timeout")
			return
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	resp, err := s.Batur.RequestNode(ctx, id, node)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, api.ErrUnknownSession) {
			code = http.StatusNotFound
		} else if errors.Is(err, api.ErrNotOnline) {
			code = http.StatusConflict
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type textRequest struct {
	To   string `json:"to"`
	Text string `json:"text"`
}

func (s *Server) hSessionText(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.bodyLimit())
	var req textRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad request json")
		return
	}
	if req.To == "" {
		writeErr(w, http.StatusBadRequest, "to/text required")
		return
	}
	_, err := s.Batur.SendText(r.Context(), r.PathValue("id"),
		api.Target{JID: req.To}, req.Text)
	if errors.Is(err, api.ErrNoBundleSource) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "no bundle source configured for this engine instance",
		})
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// hSessionSync triggers a resumable sync run for one session.
func (s *Server) hSessionSync(w http.ResponseWriter, r *http.Request) {
	if err := s.Batur.RunSync(r.Context(), r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "unknown session") {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) hSessionContacts(w http.ResponseWriter, r *http.Request) {
	list, err := s.Batur.Contacts(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"contacts": list})
}

func (s *Server) hSessionChats(w http.ResponseWriter, r *http.Request) {
	list, err := s.Batur.Chats(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chats": list})
}

// hSessionHistory serves bounded message history: ?chat=JID&limit=N
// &cursor=O without a chat param it returns the chat index. cursor
// is an offset into the chat's ring buffer (0 = oldest).
func (s *Server) hSessionHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	chat := r.URL.Query().Get("chat")
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	} else if limit > 500 {
		limit = 500
	}
	cursor := 0
	if v := r.URL.Query().Get("cursor"); v != "" {
		fmt.Sscanf(v, "%d", &cursor)
	}
	if chat == "" {
		chats, err := s.Batur.RecentChats(r.Context(), id)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"chats": chats})
		return
	}
	// Fetch the full chat ring (bounded by api.HistoryWindow) so we can
	// slice by cursor without losing pagination state.
	list, err := s.Batur.History(r.Context(), id, chat, api.HistoryWindow)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if cursor >= len(list) {
		writeJSON(w, http.StatusOK, map[string]any{"chat": chat, "messages": []any{}, "next_cursor": -1})
		return
	}
	end := cursor + limit
	if end > len(list) {
		end = len(list)
	}
	page := list[cursor:end]
	next := -1
	if end < len(list) {
		next = end
	}
	writeJSON(w, http.StatusOK, map[string]any{"chat": chat, "messages": page, "next_cursor": next})
}

// hSessionHistoryOne serves a single message by id, optionally narrowed
// to a chat via ?chat=<jid>. Returns 404 when no entry matches.
func (s *Server) hSessionHistoryOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	msgID := r.PathValue("msgID")
	chat := r.URL.Query().Get("chat")
	msg, err := s.Batur.HistoryOne(r.Context(), id, msgID, chat)
	if err != nil {
		if errors.Is(err, api.ErrUnknownMessage) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

// hEvents streams engine events as Server-Sent Events. Optional
// query params narrow the stream:
//
//	?session=<id>  only that session's events
//	?chat=<jid>    only events whose chat JID matches (inbound "from"
//	               or outbound "to" on the underlying node, or
//	               api.Message.Chat.JID)
func (s *Server) hEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	sessionFilter := r.URL.Query().Get("session")
	chatFilter := r.URL.Query().Get("chat")
	ch := make(chan events.Event, 256)
	bus := s.Batur.Bus()
	handle, err := bus.Subscribe("*", 256, events.PolicyDropOldest,
		func(_ context.Context, ev events.Event) {
			if sessionFilter != "" && ev.Session != sessionFilter {
				return
			}
			if chatFilter != "" && evChat(ev) != chatFilter {
				return
			}
			select {
			case ch <- ev:
			default:
			}
		})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer handle.Unsubscribe()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	// Emit hello.
	fmt.Fprintf(w, "event: hello\ndata: {\"engine\":\"baturwhatsapi\",\"version\":%q}\n\n", version.Version)
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case ev := <-ch:
			data, err := json.Marshal(map[string]any{
				"seq": ev.Seq, "type": ev.Type, "session": ev.Session,
				"time": ev.Time, "data": publicData(ev),
			})
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.Seq, ev.Type, data)
			flusher.Flush()
		}
	}
}

// publicData sanitizes what leaves the API boundary: protocol nodes are
// converted to their observability JSON form; errors to strings.
func publicData(ev events.Event) any {
	switch d := ev.Data.(type) {
	case binary.Node:
		return d
	case error:
		return d.Error()
	case string:
		return d
	default:
		return d
	}
}
