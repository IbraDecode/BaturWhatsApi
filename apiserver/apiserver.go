// Package apiserver exposes the core engine over HTTP (REST + SSE).
//
// The core NEVER depends on this package — it is one consumer of the api
// façade among several (SDKs, WebSocket). Endpoints are versioned under
// /v1. Bearer-token auth via BATUR_API_TOKEN (fail-closed: if unset the
// server binds to localhost only and refuses to start publicly).
package apiserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/version"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
)

// ErrNoToken means public binding was requested without an API token.
var ErrNoToken = errors.New("apiserver: BATUR_API_TOKEN required for non-local bind")

// Server wraps an api.Batur instance with HTTP endpoints.
type Server struct {
	Batur      *api.Batur
	Bind       string // ":8080" etc
	Token      string // bearer token; empty = require localhost bind
	EventQueue int    // per-subscriber queue (default 256)

	srv     *http.Server
	testURL string // set by tests when routed through httptest
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
	mux.HandleFunc("GET /metrics", s.hMetrics)
	mux.HandleFunc("POST /v1/sessions/{id}/sync", s.hSessionSync)
	mux.HandleFunc("GET /v1/sessions/{id}/contacts", s.hSessionContacts)
	mux.HandleFunc("GET /v1/sessions/{id}/chats", s.hSessionChats)
	s.srv = &http.Server{
		Addr:         s.Bind,
		Handler:      s.auth(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE: managed per-stream
	}
	return s, nil
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

// ListenAndServe starts the server (blocks until ctx cancels).
func (s *Server) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(sctx)
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
	writeJSON(w, code, map[string]string{"error": msg})
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
	var req iqRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	var req textRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.To == "" {
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

// hEvents streams engine events as Server-Sent Events.
func (s *Server) hEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ch := make(chan events.Event, 256)
	bus := s.Batur.Bus()
	handle, err := bus.Subscribe("*", 256, events.PolicyDropOldest,
		func(_ context.Context, ev events.Event) {
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
