// Command batur is the BaturWhatsApi runtime entrypoint.
//
//	batur version            — print build identity
//	batur doctor             — environment + self-check report
//	batur bench              — codec/security micro-benchmarks
//	batur demo               — run the engine against an in-process mock
//	                          WhatsApp-web server end to end
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ibradecode/baturwhatsapi/api"
	"github.com/ibradecode/baturwhatsapi/apiserver"
	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/internal/mockserver"
	"github.com/ibradecode/baturwhatsapi/internal/pairing"
	"github.com/ibradecode/baturwhatsapi/internal/version"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/e2e"
	"github.com/ibradecode/baturwhatsapi/security/noise"
	"github.com/ibradecode/baturwhatsapi/security/wacert"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
	"github.com/ibradecode/baturwhatsapi/transport"
	"github.com/ibradecode/baturwhatsapi/transport/ws"
)

func main() {
	showVersion := flag.Bool("version", false, "print engine identity and exit")
	flag.Usage = usage
	flag.Parse()
	if *showVersion {
		versionCmd()
		return
	}
	args := flag.Args()
	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
	}
	var err error
	switch cmd {
	case "version":
		versionCmd()
	case "doctor":
		err = doctor()
	case "bench":
		err = bench()
	case "demo":
		err = demo()
	case "serve":
		err = serve()
	case "keygen":
		err = keygen()
	case "pair":
		err = pair()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		// ErrSkip is the soft signal emitted by `batur doctor` when the
		// caller explicitly opted out of a check via --skip-engine /
		// --skip-e2e; exit 2 so a CI gate can tell "skipped" from "failed".
		if errors.Is(err, ErrSkipped) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: batur <version|doctor|bench|demo|serve [--bind addr] [--mock]|keygen [--output-file PATH]|pair [--mock] [--data PATH] [--device-id ID]>\n")
}

// versionCmd prints engine identity (version + channel + Go runtime).
// --json switches to a single-line machine-readable object.
func versionCmd() {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit a single JSON document instead of a human-readable line")
	_ = fs.Parse(os.Args[2:])
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]string{
			"engine":  "BaturWhatsApi",
			"version": version.Version,
			"channel": version.Channel,
			"go":      runtime.Version(),
			"goos":    runtime.GOOS,
			"goarch":  runtime.GOARCH,
		})
		return
	}
	fmt.Printf("BaturWhatsApi %s (%s) %s %s/%s\n",
		version.Version, version.Channel, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// ErrSkipped is a sentinel returned by subcommands when their work was
// deliberately opted out (e.g. `batur doctor --skip-engine`). main()
// translates it into exit code 2 so a CI gate can distinguish "skipped"
// from "failed" (exit 1) or "ok" (exit 0).
var ErrSkipped = errors.New("skipped")

// applyLogOpts reconfigures the global slog default with the chosen
// level and format. Called from serve() before any logger is in use.
func applyLogOpts(level, format string) error {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "", "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return fmt.Errorf("invalid --log-level %q (debug|info|warn|error)", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "", "text":
		h = slog.NewTextHandler(os.Stderr, opts)
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default:
		return fmt.Errorf("invalid --log-format %q (text|json)", format)
	}
	slog.SetDefault(slog.New(h))
	return nil
}

func doctor() error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit a single JSON document instead of human-readable lines")
	skipEngine := fs.Bool("skip-engine", false, "skip the engine self-check (requires in-process mock dial)")
	skipE2E := fs.Bool("skip-e2e", false, "skip the e2e X3DH+DR handshake self-check")
	_ = fs.Parse(os.Args[2:])
	type doctorReport struct {
		Go             string `json:"go"`
		GOOS           string `json:"goos"`
		GOARCH         string `json:"goarch"`
		CPUs           int    `json:"cpus"`
		Goroutines     int    `json:"goroutines"`
		TokenDict      string `json:"token_dict"`
		X25519KeygenNs int64  `json:"x25519_keygen_ns"`
		CodecWarmNs    int64  `json:"codec_warm_ns"`
		CodecWarmBytes int    `json:"codec_warm_bytes"`
		CodecWarmErr   string `json:"codec_warm_err,omitempty"`
		EngineOnlineNs int64  `json:"engine_online_ns,omitempty"`
		E2ESelfCheckNs int64  `json:"e2e_selfcheck_ns,omitempty"`
	}
	rep := doctorReport{
		Go:         runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		CPUs:       runtime.NumCPU(),
		Goroutines: runtime.NumGoroutine(),
	}
	dict := token.Default()
	rep.TokenDict = dict.String()
	start := time.Now()
	if _, err := noise.NewKeyPair(); err != nil {
		return err
	}
	rep.X25519KeygenNs = time.Since(start).Nanoseconds()
	start = time.Now()
	node := binary.Node{Tag: "iq", Attrs: binary.Attrs{"id": hexID(), "type": "set"}}
	raw := binary.MarshalDict(node, dict)
	_, err := binary.Decode(dict, raw)
	rep.CodecWarmNs = time.Since(start).Nanoseconds()
	rep.CodecWarmBytes = len(raw)
	if err != nil {
		rep.CodecWarmErr = err.Error()
	}
	start = time.Now()
	if !*skipEngine {
		srv, err := mockserver.New(dict)
		if err != nil {
			return err
		}
		dialer := mockserver.Dialer{Srv: srv}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s, err := session.New(session.Options{ID: "doctor-" + hexID()[:6], Dialer: dialer, Dict: dict,
			Device: session.DeviceInfo{Platform: "web", DeviceName: "doctor"}})
		if err != nil {
			return err
		}
		s.ServerAuth = session.TrustedRootAuth(srv.RootPub())
		if err := s.Start(ctx); err != nil {
			return fmt.Errorf("engine self-check connect: %w", err)
		}
		rep.EngineOnlineNs = time.Since(start).Nanoseconds()
		if err := s.Stop(ctx); err != nil {
			return err
		}
	}
	start = time.Now()
	if !*skipE2E {
		bk, bundle, err := e2e.NewBobKeys()
		if err != nil {
			return err
		}
		aid, err := e2e.NewIdentity()
		if err != nil {
			return err
		}
		ra, err := e2e.AliceSession(bundle, aid, e2e.ProtocolInfoV1)
		if err != nil {
			return err
		}
		env, err := ra.Encrypt([]byte("doctor"))
		if err != nil {
			return err
		}
		_, plain, err := e2e.BobSession(bk, env, e2e.ProtocolInfoV1)
		if err != nil || string(plain) != "doctor" {
			return fmt.Errorf("e2e self-check failed: %v", err)
		}
		rep.E2ESelfCheckNs = time.Since(start).Nanoseconds()
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(rep)
	}
	fmt.Printf("go:        %s (%s/%s)\n", rep.Go, rep.GOOS, rep.GOARCH)
	fmt.Printf("cpus:      %d\n", rep.CPUs)
	fmt.Printf("goroutines: %d\n", rep.Goroutines)
	fmt.Printf("token dict: %s\n", rep.TokenDict)
	fmt.Printf("x25519 keygen: %v\n", time.Duration(rep.X25519KeygenNs).Round(time.Microsecond))
	fmt.Printf("codec warm: %v (%d bytes) err=%v\n",
		time.Duration(rep.CodecWarmNs).Round(time.Microsecond), rep.CodecWarmBytes, err)
	if !*skipEngine {
		fmt.Printf("engine self-check: ONLINE in %v\n", time.Duration(rep.EngineOnlineNs).Round(time.Millisecond))
	} else {
		fmt.Println("engine self-check: skipped")
	}
	if !*skipE2E {
		fmt.Printf("e2e self-check: X3DH+DR handshake ok in %v\n",
			time.Duration(rep.E2ESelfCheckNs).Round(time.Millisecond))
	} else {
		fmt.Println("e2e self-check: skipped")
	}
	if *skipEngine && *skipE2E {
		return ErrSkipped
	}
	return nil
}

func bench() error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit a single JSON document instead of human-readable lines")
	_ = fs.Parse(os.Args[2:])
	dict := token.Default()
	node := binary.Node{Tag: "message", Attrs: binary.Attrs{
		"from": "628123456789@s.whatsapp.net", "id": hexID(), "type": "text",
		"t": "1690000000",
	}, Content: []binary.Node{{Tag: "plain", Content: "Benchmark text payload for the batur engine codec layer."}}}
	raw := binary.MarshalDict(node, dict)

	const n = 200000
	start := time.Now()
	for i := 0; i < n; i++ {
		_ = binary.MarshalDict(node, dict)
	}
	enc := time.Since(start)
	start = time.Now()
	for i := 0; i < n; i++ {
		if _, err := binary.Decode(dict, raw); err != nil {
			return err
		}
	}
	dec := time.Since(start)
	start = time.Now()
	const hn = 5000
	for i := 0; i < hn; i++ {
		if _, err := noise.NewKeyPair(); err != nil {
			return err
		}
	}
	keygen := time.Since(start)

	if *asJSON {
		type benchReport struct {
			NodeEncodeOps       int     `json:"node_encode_ops"`
			NodeEncodeNs        int64   `json:"node_encode_ns"`
			NodeEncodeOpsPerSec float64 `json:"node_encode_ops_per_sec"`
			NodeDecodeOps       int     `json:"node_decode_ops"`
			NodeDecodeNs        int64   `json:"node_decode_ns"`
			NodeDecodeOpsPerSec float64 `json:"node_decode_ops_per_sec"`
			X25519KeygenOps     int     `json:"x25519_keygen_ops"`
			X25519KeygenNs      int64   `json:"x25519_keygen_ns"`
			X25519OpsPerSec     float64 `json:"x25519_ops_per_sec"`
		}
		rep := benchReport{
			NodeEncodeOps:       n,
			NodeEncodeNs:        enc.Nanoseconds(),
			NodeEncodeOpsPerSec: float64(n) / enc.Seconds(),
			NodeDecodeOps:       n,
			NodeDecodeNs:        dec.Nanoseconds(),
			NodeDecodeOpsPerSec: float64(n) / dec.Seconds(),
			X25519KeygenOps:     hn,
			X25519KeygenNs:      keygen.Nanoseconds(),
			X25519OpsPerSec:     float64(hn) / keygen.Seconds(),
		}
		enc2 := json.NewEncoder(os.Stdout)
		enc2.SetEscapeHTML(false)
		return enc2.Encode(rep)
	}

	fmt.Printf("node encode: %d ops in %v (%.0f ops/s)\n", n, enc.Round(time.Millisecond), float64(n)/enc.Seconds())
	fmt.Printf("node decode: %d ops in %v (%.0f ops/s)\n", n, dec.Round(time.Millisecond), float64(n)/dec.Seconds())
	fmt.Printf("x25519 keygen: %d in %v (%.0f/s)\n", hn, keygen.Round(time.Millisecond), float64(hn)/keygen.Seconds())
	return nil
}

// keygen generates a 32-byte (64-hex) master key suitable for the
// --seal-key flag / BATUR_MASTER_KEY env. With --output-file it writes
// the key atomically with 0600 perms instead of printing it.
func keygen() error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	output := fs.String("output-file", "", "write the key to this path with 0600 perms (atomic temp+rename)")
	_ = fs.Parse(os.Args[2:])
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	hexed := fmt.Sprintf("%x\n", key)
	if *output == "" {
		fmt.Print(hexed)
		return nil
	}
	tmp := *output + ".tmp"
	if err := os.WriteFile(tmp, []byte(hexed), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, *output); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote 32-byte master key to %s (0600)\n", *output)
	return nil
}

func demo() error {
	dict := token.Default()
	srv, err := mockserver.New(dict)
	if err != nil {
		return err
	}
	dialer := mockserver.Dialer{Srv: srv}
	bus := events.New()
	defer bus.Close()
	b, err := api.New(api.Options{Bus: bus, Dict: dict})
	if err != nil {
		return err
	}
	if _, err := bus.Subscribe("*", 64, events.PolicyBlock, func(_ context.Context, ev events.Event) {
		fmt.Printf("[event] %s session=%s data=%v\n", ev.Type, ev.Session, compact(ev))
	}); err != nil {
		return err
	}
	if err := b.Attach("demo-device", dialer, session.TrustedRootAuth(srv.RootPub()),
		session.DeviceInfo{Platform: "web", DeviceName: "demo"}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := b.Start(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := b.Status("demo-device")
		if err == nil && st.State == api.StateOnline {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("demo complete")
	return b.Stop(context.Background())
}

func compact(ev events.Event) string {
	switch d := ev.Data.(type) {
	case binary.Node:
		return fmt.Sprintf("<%s id=%s>", d.Tag, d.MustStringAttr("id"))
	case statemachine.State:
		return string(d)
	default:
		return fmt.Sprintf("%v", d)
	}
}

func serve() error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	bind := fs.String("bind", "127.0.0.1:8080", "HTTP bind address")
	data := fs.String("data", "", "session data directory (empty = ephemeral in-memory)")
	mock := fs.Bool("mock", false, "run with the in-process mock WhatsApp-web server (API development)")
	sealKey := fs.String("seal-key", "", "64-hex master key sealing secrets at rest (or $BATUR_MASTER_KEY, or --seal-key-file)")
	sealFile := fs.String("seal-key-file", "", "file containing the master key hex")
	history := fs.Bool("history", true, "persist bounded per-chat message history")
	sync := fs.Bool("sync", false, "auto-sync contacts/chats on session ready")
	mediaDemo := fs.Bool("media-demo", false, "with --mock: additionally push an <image/> message right after connect")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	logFormat := fs.String("log-format", "text", "log format: text|json")
	maxBody := fs.Int("max-body-bytes", 1<<20, "cap on POST request body bytes (HTTP 413 when exceeded)")
	readTimeout := fs.Duration("http-read-timeout", 15*time.Second, "HTTP server ReadTimeout (0 = no limit)")
	wsPing := fs.Duration("ws-ping-interval", 25*time.Second, "WS bridge keepalive ping interval (0 disables)")
	_ = fs.Parse(os.Args[2:])
	if err := applyLogOpts(*logLevel, *logFormat); err != nil {
		return err
	}

	dict := token.Default()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var ao api.Options = api.Options{Dict: dict, History: *history, Sync: api.SyncOptions{Enabled: *sync}}
	masterHex := strings.TrimSpace(*sealKey)
	if masterHex == "" {
		masterHex = os.Getenv("BATUR_MASTER_KEY")
	}
	if masterHex == "" && *sealFile != "" {
		pem, rerr := os.ReadFile(*sealFile)
		if rerr != nil {
			return rerr
		}
		masterHex = strings.TrimSpace(string(pem))
	}
	if masterHex != "" {
		mk, kerr := storage.MasterKeyFromHex(masterHex)
		if kerr != nil {
			return kerr
		}
		ao.MasterKey = mk
		slog.Info("secrets-at-rest sealing enabled (AES-256-GCM)")
	}
	if *data != "" {
		store, err := storage.NewFileStore(*data)
		if err != nil {
			return err
		}
		defer store.Close()
		ao.Store = store
	}
	var b *api.Batur
	var pairDialer transport.Dialer
	var pairAuth session.ServerAuth
	if *mock {
		srv, err := mockserver.New(dict)
		if err != nil {
			return err
		}
		srv.MediaDemo = *mediaDemo
		ao.BundleSource = func(context.Context, api.Target) (*e2e.PreKeyBundle, error) {
			return srv.E2EBundle(), nil
		}
		b, err = api.New(ao)
		if err != nil {
			return err
		}
		dialer := mockserver.Dialer{Srv: srv}
		auth := session.TrustedRootAuth(srv.RootPub())
		pairDialer, pairAuth = dialer, auth
		ids, err := attachFleet(b, dialer, auth, ao.Store)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			if err := b.Attach("mock-1", dialer, auth,
				session.DeviceInfo{Platform: "web", DeviceName: "serve-mock"}); err != nil {
				return err
			}
			ids = []string{"mock-1"}
		}
		if err := b.Start(ctx); err != nil {
			return err
		}
		slog.Info("serve: mock fleet attached", "sessions", strings.Join(ids, ","), "data", *data)
	} else {
		return fmt.Errorf("real WhatsApp-web dialer/registration is pending (docs/TASKS.md T-101..T-103); use --mock for now")
	}
	apiSrv, err := apiserver.New(&apiserver.Server{
		Batur: b, Bind: *bind, Token: os.Getenv("BATUR_API_TOKEN"),
		MaxBodyBytes:   int64(*maxBody),
		ReadTimeout:    *readTimeout,
		WSPingInterval: *wsPing,
		PairDialer:     pairDialer,
		PairAuth:       pairAuth,
	})
	if err != nil {
		return err
	}
	slog.Info("HTTP API listening", "bind", *bind, "auth", os.Getenv("BATUR_API_TOKEN") != "",
		"history", *history, "sync", *sync, "max_body_bytes", *maxBody, "read_timeout", readTimeout.String(),
		"ws_ping_interval", wsPing.String())
	go func() {
		if err := apiSrv.ListenAndServe(ctx); err != nil {
			slog.Error("http server", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	slog.Info("shutting down")
	return b.Stop(context.Background())
}

// whatsAppDial is the live WhatsApp Web control-socket dial: Origin plus
// the "WA" + magic + dictionary-version prefix and 3-byte length frames.
func whatsAppDial() ws.Options {
	return ws.Options{
		HandshakeTimeout: 30 * time.Second,
		Header: http.Header{
			"Origin": []string{"https://web.whatsapp.com"},
		},
		FramePrefix:  []byte{'W', 'A', 6, byte(token.Default().Version)},
		LengthPrefix: true,
	}
}

type fleetRec struct {
	SessionID string `json:"session_id"`
	Account   string `json:"account"`
	Platform  string `json:"platform"`
	Name      string `json:"name"`
}

func attachFleet(b *api.Batur, dialer transport.Dialer, auth session.ServerAuth, store storage.KV) ([]string, error) {
	if store == nil {
		return nil, nil
	}
	keys, err := store.List(context.Background(), "fleet/")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, key := range keys {
		raw, err := store.Get(context.Background(), key)
		if err != nil {
			return nil, err
		}
		var rec fleetRec
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("fleet record %s: %w", key, err)
		}
		if rec.SessionID == "" {
			continue
		}
		plat, name := rec.Platform, rec.Name
		if plat == "" {
			plat = "web"
		}
		if name == "" {
			name = "batur"
		}
		if err := b.Attach(rec.SessionID, dialer, auth, session.DeviceInfo{Platform: plat, DeviceName: name}); err != nil {
			return nil, err
		}
		ids = append(ids, rec.SessionID)
	}
	return ids, nil
}

func pair() error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	deviceID := fs.String("device-id", "", "unique device identifier (auto-generated if empty)")
	deviceName := fs.String("device-name", "batur", "device display name")
	platform := fs.String("platform", "web", "platform identifier (web, desktop, etc.)")
	edgeServer := fs.String("edge", "wss://web.whatsapp.com/ws/chat", "edge WebSocket URL")
	dataDir := fs.String("data", "", "session data directory (same flag as serve; empty = in-memory)")
	mock := fs.Bool("mock", false, "pair against an in-process mock server (no network)")
	qrWait := fs.Duration("qr-timeout", 5*time.Minute, "how long to wait for the QR scan")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	logFormat := fs.String("log-format", "text", "log format: text|json")
	_ = fs.Parse(os.Args[2:])

	if err := applyLogOpts(*logLevel, *logFormat); err != nil {
		return err
	}
	if *deviceID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		*deviceID = fmt.Sprintf("batur-%x", b)
		slog.Info("generated device ID", "device_id", *deviceID)
	}

	var store storage.KV
	if *dataDir != "" {
		s, err := storage.NewFileStore(*dataDir)
		if err != nil {
			return err
		}
		defer s.Close()
		store = s
	} else {
		store = storage.NewMemory()
	}

	var dialer transport.Dialer
	auth := session.TrustedRootAuth(wacert.RootPubKey)
	edge := *edgeServer
	if *mock {
		srv, err := mockserver.New(token.Default())
		if err != nil {
			return err
		}
		dialer = mockserver.Dialer{Srv: srv}
		auth = session.TrustedRootAuth(srv.RootPub())
		edge = "mock://pair"
	} else {
		dialer = ws.NewDialer(whatsAppDial())
		if edge == "" || edge == "wss://web.whatsapp.com/ws" {
			edge = "wss://web.whatsapp.com/ws/chat"
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := pairing.PairingConfig{
		EdgeServer: edge,
		DeviceID:   *deviceID,
		DeviceName: *deviceName,
		Platform:   *platform,
		Dialer:     dialer,
		ServerAuth: auth,
		Logger:     slog.Default().With("comp", "pair"),
		QRCallback: func(code, ref string, expiresAt time.Time) error {
			fmt.Println("\n=== Batur pairing ===")
			fmt.Printf("Code:    %s\n", code)
			fmt.Printf("Ref:     %s\n", ref)
			if !expiresAt.IsZero() {
				fmt.Printf("Expires: %s\n", expiresAt.Format(time.RFC3339))
			}
			fmt.Println("Waiting for the linked device to confirm...")
			return nil
		},
		QRTimeout: *qrWait,
	}

	slog.Info("starting pairing", "device_id", *deviceID, "edge", edge, "mock", *mock)
	result, err := pairing.Pair(ctx, cfg)
	if err != nil {
		return fmt.Errorf("pairing failed: %w", err)
	}

	eng, err := api.New(api.Options{Store: store})
	if err != nil {
		return err
	}
	if err := eng.RememberPair(ctx, result.DeviceID, session.Credentials{
		NoiseKeySeed:   result.NoiseKeySeed,
		RegistrationID: result.RegistrationID,
		DeviceID:       result.DeviceID,
		AccountJID:     result.AccountJID,
		ServerStatic:   result.ServerStatic,
	}, session.DeviceInfo{Platform: *platform, DeviceName: *deviceName}); err != nil {
		return fmt.Errorf("store credentials: %w", err)
	}
	slog.Info("credentials stored", "session", result.DeviceID)

	fmt.Printf("\nPairing complete\n")
	fmt.Printf("  Account: %s\n", result.AccountJID)
	fmt.Printf("  Device:  %s\n", result.DeviceID)
	if *dataDir != "" {
		fmt.Printf("  Stored:  %s\n", *dataDir)
		fmt.Printf("\nNext: batur serve --data %s\n", *dataDir)
	}
	return nil
}

func hexID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
