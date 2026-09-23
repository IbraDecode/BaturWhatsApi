package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	// Subscribe (unfiltered) so events flow.
	sub, _ := json.Marshal(map[string]string{"op": "subscribe"})
	if err := c.SendText(wctx, sub); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		raw, err := c.ReceiveBinary(wctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"subscribe"`)) {
			break
		}
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
	sub2, _ := json.Marshal(map[string]string{"op": "subscribe", "session": "wsdev"})
	if err := c.SendText(wctx, sub2); err != nil {
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

func TestWSBridgeChatFilter(t *testing.T) {
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
	if err := b.Attach("wsflt", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := b.Status("wsflt"); err == nil && st.State == api.StateOnline {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	acct, err := b.Status("wsflt")
	if err != nil {
		t.Fatal(err)
	}
	if acct.Account == "" {
		t.Fatal("online without account")
	}

	s := &Server{Batur: b}
	s, err = New(s)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/ws"

	d := ws.NewDialer(ws.Options{})
	wctx, wcancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer wcancel()
	c, err := d.Dial(wctx, wsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.ReceiveBinary(wctx); err != nil { // hello
		t.Fatal(err)
	}

	// Subscribe filtered to an unrelated chat JID: send results still flow,
	// but message events from the real account must NOT.
	other := "999@s.whatsapp.net"
	sub, _ := json.Marshal(map[string]string{"op": "subscribe", "session": "wsflt", "jid": other})
	if err := c.SendText(wctx, sub); err != nil {
		t.Fatal(err)
	}
	gotSub := false
	for i := 0; i < 20 && !gotSub; i++ {
		raw, err := c.ReceiveBinary(wctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"subscribe"`)) {
			gotSub = true
		}
	}
	if !gotSub {
		t.Fatal("no subscribe result")
	}

	// send to the real account: expect a send result but NO message.sent event.
	cmd, _ := json.Marshal(map[string]string{"op": "send", "session": "wsflt", "to": acct.Account, "text": "filter me"})
	if err := c.SendText(wctx, cmd); err != nil {
		t.Fatal(err)
	}
	sawResult, sawEvent := false, false
	rc, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	for !sawResult {
		raw, err := c.ReceiveBinary(rc)
		if err != nil {
			break
		}
		if bytes.Contains(raw, []byte(`"message.sent"`)) {
			sawEvent = true
		}
		if bytes.Contains(raw, []byte(`"send"`)) && bytes.Contains(raw, []byte(`"ok":true`)) {
			sawResult = true
		}
	}
	rcancel()
	if !sawResult {
		t.Fatal("no send result under chat filter")
	}
	if sawEvent {
		t.Fatalf("message.sent leaked through %s chat filter", other)
	}

	// Re-subscribe to the real chat and verify events flow again.
	sub2, _ := json.Marshal(map[string]string{"op": "subscribe", "session": "wsflt", "jid": acct.Account})
	if err := c.SendText(wctx, sub2); err != nil {
		t.Fatal(err)
	}
	cmd2, _ := json.Marshal(map[string]string{"op": "send", "session": "wsflt", "to": acct.Account, "text": "show me"})
	if err := c.SendText(wctx, cmd2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		raw, err := c.ReceiveBinary(wctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"message.sent"`)) {
			return
		}
	}
	t.Fatal("message.sent never arrived after re-subscribe to real chat")
}

func TestWSBridgeUnsubscribe(t *testing.T) {
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
	if err := b.Attach("wsun", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := b.Status("wsun"); err == nil && st.State == api.StateOnline {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	acct, err := b.Status("wsun")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Batur: b}
	s, err = New(s)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/ws"
	d := ws.NewDialer(ws.Options{})
	wctx, wcancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer wcancel()
	c, err := d.Dial(wctx, wsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.ReceiveBinary(wctx); err != nil {
		t.Fatal(err)
	}

	sub, _ := json.Marshal(map[string]string{"op": "subscribe", "session": "wsun", "jid": acct.Account})
	if err := c.SendText(wctx, sub); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		raw, _ := c.ReceiveBinary(wctx)
		if bytes.Contains(raw, []byte(`"subscribe"`)) {
			break
		}
	}

	// Send -> message.sent visible.
	cmd, _ := json.Marshal(map[string]string{"op": "send", "session": "wsun", "to": acct.Account, "text": "on"})
	if err := c.SendText(wctx, cmd); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		raw, err := c.ReceiveBinary(wctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"message.sent"`)) {
			break
		}
		if i == 59 {
			t.Fatal("message.sent never arrived before unsubscribe")
		}
	}

	// Unsubscribe -> send another, event must NOT arrive.
	unsub, _ := json.Marshal(map[string]string{"op": "unsubscribe"})
	if err := c.SendText(wctx, unsub); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		raw, _ := c.ReceiveBinary(wctx)
		if bytes.Contains(raw, []byte(`"unsubscribe"`)) {
			break
		}
	}

	cmd2, _ := json.Marshal(map[string]string{"op": "send", "session": "wsun", "to": acct.Account, "text": "off"})
	if err := c.SendText(wctx, cmd2); err != nil {
		t.Fatal(err)
	}
	rc, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer rcancel()
	for {
		raw, err := c.ReceiveBinary(rc)
		if err != nil {
			return // timed out without seeing message.sent -> pass
		}
		if bytes.Contains(raw, []byte(`"message.sent"`)) {
			t.Fatal("message.sent leaked after unsubscribe")
		}
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

func TestHistoryPagination(t *testing.T) {
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
	if err := b.Attach("page", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	deadline := time.Now().Add(10 * time.Second)
	var acct string
	for time.Now().Before(deadline) {
		if st, err := b.Status("page"); err == nil && st.State == api.StateOnline && st.Account != "" {
			acct = st.Account
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if acct == "" {
		t.Fatal("never online")
	}
	const N = 8
	for i := 0; i < N; i++ {
		if _, err := b.SendText(ctx, "page", api.Target{JID: acct}, fmt.Sprintf("msg-%02d", i)); err != nil {
			t.Fatal(err)
		}
	}
	// wait for persistence
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h, err := b.History(ctx, "page", acct, 64)
		if err == nil && len(h) >= N {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	s := &Server{Batur: b}
	s, err = New(s)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()

	get := func(qs string) map[string]any {
		resp, err := http.Get(ts.URL + "/v1/sessions/page/history?" + qs + "&chat=" + url.QueryEscape(acct))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b1, _ := io.ReadAll(resp.Body)
		var out map[string]any
		if err := json.Unmarshal(b1, &out); err != nil {
			t.Fatalf("bad json %s: %v", b1, err)
		}
		return out
	}
	first := get("limit=3")
	msgs := first["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("page1 len = %d want 3", len(msgs))
	}
	firstID, _ := msgs[0].(map[string]any)["id"].(string)
	next, _ := first["next_cursor"].(float64)
	if int(next) <= 0 {
		t.Fatalf("next_cursor not set: %v", first["next_cursor"])
	}
	second := get(fmt.Sprintf("limit=3&cursor=%d", int(next)))
	msgs2 := second["messages"].([]any)
	if len(msgs2) == 0 {
		t.Fatal("page2 empty")
	}
	firstID2, _ := msgs2[0].(map[string]any)["id"].(string)
	if firstID == firstID2 {
		t.Fatal("pages overlap")
	}
	// Drain everything and confirm full coverage.
	seen := map[string]bool{firstID: true}
	for _, m := range msgs {
		if id, ok := m.(map[string]any)["id"].(string); ok {
			seen[id] = true
		}
	}
	for _, m := range msgs2 {
		if id, ok := m.(map[string]any)["id"].(string); ok {
			seen[id] = true
		}
	}
	c, _ := second["next_cursor"].(float64)
	for c >= 0 {
		pg := get(fmt.Sprintf("limit=3&cursor=%d", int(c)))
		for _, m := range pg["messages"].([]any) {
			if id, ok := m.(map[string]any)["id"].(string); ok {
				seen[id] = true
			}
		}
		nc, _ := pg["next_cursor"].(float64)
		if nc == c {
			break
		}
		c = nc
	}
	if len(seen) < N {
		t.Fatalf("paginated coverage %d < %d", len(seen), N)
	}
}

func TestSSEFilter(t *testing.T) {
	s, _, cleanup, b := newTestServerEx(t, "", false)
	defer cleanup()
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitOnlineSimple(t, s)
	// subscribe SSE with a wrong chat filter: nothing should arrive for ~700ms
	req, _ := http.NewRequest("GET", s.testURL+"/v1/events?chat=999@s.whatsapp.net", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	deadline := time.After(700 * time.Millisecond)
	for {
		select {
		case <-deadline:
			return // no message.* event leaked through filter -> pass
		default:
		}
		if !scanner.Scan() {
			t.Fatal("SSE closed prematurely")
		}
		line := scanner.Text()
		if strings.Contains(line, `"message.sent"`) {
			t.Fatalf("message.sent leaked through %s chat filter: %s", "999@s.whatsapp.net", line)
		}
	}
}

func TestMaxBodyBytes(t *testing.T) {
	s, _, cleanup, _ := newTestServerEx(t, "", false)
	defer cleanup()
	// Override limit to 256 bytes so we don't need to send 1MiB in a test.
	s.MaxBodyBytes = 256
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'x'
	}
	resp, err := http.Post(ts.URL+"/v1/sessions/http-dev/text", "application/json", strings.NewReader(`{"to":"x","text":"`+string(big)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		b1, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, b1)
	}
}

func TestHistoryOne(t *testing.T) {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		t.Fatal(err)
	}
	dialer := mockserver.Dialer{Srv: srv}
	b, err := api.New(api.Options{Dict: dict, History: true, Store: storage.NewMemory(),
		BundleSource: func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Attach("http-dev", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	s := &Server{Batur: b}
	s, err = New(s)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {}
	_ = cleanup
	waitOnlineSimple(t, s)
	st, err := b.Status("http-dev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.SendText(context.Background(), "http-dev", api.Target{JID: st.Account}, "history-one"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var found string
	for time.Now().Before(deadline) {
		h, err := b.History(context.Background(), "http-dev", st.Account, 64)
		if err == nil {
			for _, m := range h {
				if m.Text == "history-one" {
					found = m.ID
					break
				}
			}
		}
		if found != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if found == "" {
		t.Fatal("message never reached history")
	}
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/v1/sessions/http-dev/history/" + found + "?chat=" + url.QueryEscape(st.Account))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b1, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, b1)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != found {
		t.Fatalf("id = %v want %s", got["id"], found)
	}
	if got["text"] != "history-one" {
		t.Fatalf("text = %v", got["text"])
	}
	// Missing message -> 404
	resp2, err := http.Get(ts.URL + "/v1/sessions/http-dev/history/does-not-exist?chat=" + url.QueryEscape(st.Account))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status=%d", resp2.StatusCode)
	}
}
