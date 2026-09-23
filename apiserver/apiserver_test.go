package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/e2e"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
	"github.com/ibradecode/baturwhatsapi/transport/ws"
)

func newTestServer(t *testing.T, tokenAuth string) (*Server, *mockserver.Server, func()) {
	s, _, cleanup, _ := newTestServerEx(t, tokenAuth, true)
	return s, nil, cleanup
}

func newTestServerEx(t *testing.T, tokenAuth string, start bool) (*Server, *mockserver.Server, func(), *api.Batur) {
	t.Helper()
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	b, err := api.New(api.Options{Dict: dict, Store: storage.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("http-dev", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web", DeviceName: "http"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if start {
		if err := b.Start(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
	}
	s := &Server{Batur: b, Token: tokenAuth, EventQueue: 64}
	s, err = New(s)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	// Route through httptest via the handler; ListenAndServe uses Addr but
	// tests call serveMux directly.
	ts := httptest.NewServer(s.srv.Handler)
	cleanup := func() {
		ts.Close()
		b.Stop(context.Background())
		cancel()
	}
	s.testURL = ts.URL
	return s, srv, cleanup, b
}

func waitOnline(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(s.testURL + "/v1/sessions/http-dev")
		if err == nil {
			var st api.SessionStatus
			json.NewDecoder(resp.Body).Decode(&st)
			resp.Body.Close()
			if st.State == api.StateOnline {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("session never reached ONLINE via API")
}

func TestHealthAndAuth(t *testing.T) {
	s, _, cleanup := newTestServer(t, "secret-token")
	defer cleanup()
	// health is public.
	resp, err := http.Get(s.testURL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health code = %d", resp.StatusCode)
	}
	// sessions require token.
	if r, _ := http.Get(s.testURL + "/v1/sessions"); r.StatusCode != 401 {
		t.Fatalf("no-token status = %d", r.StatusCode)
	}
	req, _ := http.NewRequest("GET", s.testURL+"/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
		t.Fatal("valid token rejected")
	}
}

func TestPublicBindRequiresToken(t *testing.T) {
	_, err := New(&Server{Batur: &api.Batur{}, Bind: "0.0.0.0:8080"})
	if err != ErrNoToken {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
}

func TestIQBridge(t *testing.T) {
	s, _, cleanup := newTestServer(t, "")
	defer cleanup()
	waitOnline(t, s)
	body := `{"tag":"iq","attrs":{"type":"get","xmlns":"batur.demo"},
		"content":[{"tag":"echo","attrs":{"msg":"via-http"}}],"timeout":"5s"}`
	req, _ := http.NewRequest("POST", s.testURL+"/v1/sessions/http-dev/iq",
		strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		t.Fatalf("iq status %d: %v", resp.StatusCode, e)
	}
	var node binary.Node
	if err := json.NewDecoder(resp.Body).Decode(&node); err != nil {
		t.Fatal(err)
	}
	echo, ok := node.ChildByTag("echo")
	if !ok || echo.MustStringAttr("msg") != "via-http" {
		t.Fatalf("iq response = %+v", node)
	}
}

func TestTextNotImplementedYet(t *testing.T) {
	s, _, cleanup := newTestServer(t, "")
	defer cleanup()
	waitOnline(t, s)
	resp, err := http.Post(s.testURL+"/v1/sessions/http-dev/text", "application/json",
		strings.NewReader(`{"to":"628123@s.whatsapp.net","text":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestSSEEvents(t *testing.T) {
	s, _, cleanup, b := newTestServerEx(t, "", false)
	defer cleanup()
	req, _ := http.NewRequest("GET", s.testURL+"/v1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %s", ct)
	}
	// Start the fleet only after the stream is attached: no missed edges.
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(resp.Body)
	seenOnline := false
	deadline := time.After(15 * time.Second)
	done := make(chan bool, 1)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "connection.state") && strings.Contains(line, "ONLINE") {
				done <- true
				return
			}
		}
		done <- false
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("SSE stream closed early")
		}
		seenOnline = true
	case <-deadline:
		t.Fatal("no ONLINE event over SSE within deadline")
	}
	if !seenOnline {
		t.Fatal("unreachable")
	}
}

func TestSessionDelete(t *testing.T) {
	s, _, cleanup := newTestServer(t, "")
	defer cleanup()
	waitOnline(t, s)
	req, _ := http.NewRequest("DELETE", s.testURL+"/v1/sessions/http-dev", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	r2, _ := http.Get(s.testURL + "/v1/sessions/http-dev")
	r2.Body.Close()
	if r2.StatusCode != 404 {
		t.Fatal("session still listed")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s, _, cleanup := newTestServer(t, "")
	defer cleanup()
	// force an ONLINE reading eventually
	waitOnlineSimple(t, s)
	resp, err := http.Get(s.testURL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("metrics status %d", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	for _, want := range []string{
		"batur_session_state{session=\"http-dev\"",
		"batur_goroutines ",
		"batur_heap_alloc_bytes ",
		"# TYPE batur_online_sessions gauge",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q\n%s", want, body[:min(500, len(body))])
		}
	}
}

func waitOnlineSimple(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Batur.Status("http-dev")
		if err == nil && st.State == string(statemachine.Online) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestSyncEndpoints(t *testing.T) {
	s, _, cleanup := newTestServer(t, "")
	defer cleanup()
	waitOnlineSimple(t, s)
	// trigger sync
	resp, err := http.Post(s.testURL+"/v1/sessions/http-dev/sync", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("sync status = %d", resp.StatusCode)
	}
	// read contacts
	rc, err := http.Get(s.testURL + "/v1/sessions/http-dev/contacts")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Body.Close()
	body, _ := io.ReadAll(rc.Body)
	if !strings.Contains(string(body), "Contact 0") || !strings.Contains(string(body), "62812") {
		t.Fatalf("contacts body = %s", body)
	}
	// read chats
	rh, err := http.Get(s.testURL + "/v1/sessions/http-dev/chats")
	if err != nil {
		t.Fatal(err)
	}
	defer rh.Body.Close()
	hbody, _ := io.ReadAll(rh.Body)
	if !strings.Contains(string(hbody), "\"chats\"") {
		t.Fatalf("chats body = %s", hbody)
	}
	// sync unknown session -> 404
	ru, _ := http.Post(s.testURL+"/v1/sessions/nope/sync", "application/json", nil)
	ru.Body.Close()
	if ru.StatusCode != 404 {
		t.Fatalf("unknown sync status = %d", ru.StatusCode)
	}
}

func TestHistoryEndpoint(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	b, err := api.New(api.Options{Dict: dict, History: true,
		BundleSource: func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("hist", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	for i := 0; i < 200; i++ {
		if st, err := b.Status("hist"); err == nil && st.State == api.StateOnline && st.Account != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := b.Status("hist")
	if _, err := b.SendText(ctx, "hist", api.Target{JID: st.Account}, "endpoint history"); err != nil {
		t.Fatal(err)
	}
	s := &Server{Batur: b}
	s, err = New(s)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	// wait for persistence
	var body string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(ts.URL + "/v1/sessions/hist/history?chat=" + url.QueryEscape(st.Account))
		if err != nil {
			t.Fatal(err)
		}
		b1, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body = string(b1)
		if strings.Contains(body, "endpoint history") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("message not in history endpoint: %s", body)
}

func TestWSBridge(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	b, err := api.New(api.Options{Dict: dict, Store: storage.NewMemory(),
		BundleSource: func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("wsdev", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())

	// wait online first so event assertions are deterministic
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := b.Status("wsdev"); err == nil && st.State == api.StateOnline {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	st, _ := b.Status("wsdev")

	s := &Server{Batur: b}
	s, err = New(s)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/ws"

	d := ws.NewDialer(ws.Options{})
	wctx, wcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer wcancel()
	c, err := d.Dial(wctx, wsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// hello must arrive first
	raw, err := c.ReceiveBinary(wctx)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &env) != nil || env.Type != "hello" {
		t.Fatalf("first frame not hello: %s", raw)
	}

	// send a command; expect a result (retry once on a transient failure)
	// plus a streamed message.sent event. The event goroutine and the
	// command handler run concurrently, so the event may legally arrive
	// either before or after the result: scan until both are seen.
	var gotEvent bool
	sendOK := false
	sendDone := false
	var lastSendErr string
	for attempt := 0; attempt < 2 && !(sendOK && gotEvent); attempt++ {
		cmd, _ := json.Marshal(map[string]string{"op": "send", "session": "wsdev", "to": st.Account, "text": "ws bridge"})
		if err := c.SendText(wctx, cmd); err != nil {
			t.Fatal(err)
		}
		step, scancel := context.WithTimeout(context.Background(), 8*time.Second)
	scan:
		for !(sendOK && gotEvent) {
			raw, err := c.ReceiveBinary(step)
			if err != nil {
				break scan
			}
			var top struct {
				Type  string `json:"type"`
				Op    string `json:"op"`
				Ok    bool   `json:"ok"`
				ID    string `json:"id"`
				Error string `json:"error"`
			}
			if json.Unmarshal(raw, &top) != nil {
				continue
			}
			if top.Type == "result" && top.Op == "send" {
				sendDone = true
				if top.Ok && top.ID != "" {
					sendOK = true
				} else {
					lastSendErr = top.Error
				}
			} else if top.Type == "message.sent" {
				gotEvent = true
			}
		}
		scancel()
	}
	if !sendOK {
		t.Fatalf("no send result received over ws (done=%v last error: %q)", sendDone, lastSendErr)
	}
	if !gotEvent {
		t.Fatal("no message.sent event streamed over ws")
	}

	// subscribe filter + sync command
	sub, _ := json.Marshal(map[string]string{"op": "subscribe", "session": "wsdev"})
	if err := c.SendText(wctx, sub); err != nil {
		t.Fatal(err)
	}
	done := false
	for i := 0; i < 20 && !done; i++ {
		raw, err := c.ReceiveBinary(wctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"subscribe"`)) && bytes.Contains(raw, []byte(`"ok":true`)) {
			done = true
		}
	}
	if !done {
		t.Fatal("no subscribe result received")
	}

	// sync command returns ok
	syc, _ := json.Marshal(map[string]string{"op": "sync", "session": "wsdev"})
	if err := c.SendText(wctx, syc); err != nil {
		t.Fatal(err)
	}
	sawSync := false
	for i := 0; i < 40 && !sawSync; i++ {
		raw, err := c.ReceiveBinary(wctx)
		if err != nil {
			break
		}
		if bytes.Contains(raw, []byte(`"sync"`)) && bytes.Contains(raw, []byte(`"ok":true`)) {
			sawSync = true
		}
	}
	if !sawSync {
		t.Fatal("no sync result received over ws")
	}

	// metrics expose the live connection gauge
	mr, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mbody := readAll(t, mr.Body)
	mr.Body.Close()
	if !strings.Contains(mbody, "batur_ws_connections 1") {
		t.Fatalf("ws gauge not exposed: %s", mbody)
	}
}

func TestWSBridgeTokenAuth(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	b, err := api.New(api.Options{Dict: dict, Store: storage.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("wsdev", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	s := &Server{Batur: b, Token: "ws-secret"}
	s, err = New(s)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/ws"
	d := ws.NewDialer(ws.Options{})
	wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wcancel()
	// without token -> handshake rejected
	if _, err := d.Dial(wctx, wsURL); err == nil {
		t.Fatal("upgrade without token succeeded, want rejection")
	}
	// with token -> ok
	d2 := ws.NewDialer(ws.Options{Header: http.Header{"Authorization": {"Bearer ws-secret"}}})
	c, err := d2.Dial(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("upgrade with token failed: %v", err)
	}
	defer c.Close()
	raw, err := c.ReceiveBinary(wctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"hello"`)) {
		t.Fatalf("no hello after authed upgrade: %s", raw)
	}
}
