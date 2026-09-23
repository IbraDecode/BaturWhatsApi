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
	"flag"
	"fmt"
	"log/slog"
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
	"github.com/ibradecode/baturwhatsapi/internal/version"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/e2e"
	"github.com/ibradecode/baturwhatsapi/security/noise"
	"github.com/ibradecode/baturwhatsapi/session"
	"github.com/ibradecode/baturwhatsapi/statemachine"
	"github.com/ibradecode/baturwhatsapi/storage"
)

func main() {
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
	}
	var err error
	switch cmd {
	case "version":
		fmt.Printf("BaturWhatsApi %s (%s) %s\n", version.Version, version.Channel, runtime.Version())
	case "doctor":
		err = doctor()
	case "bench":
		err = bench()
	case "demo":
		err = demo()
	case "serve":
		err = serve()
	case "keygen":
		key := make([]byte, 32)
		_, rerr := rand.Read(key)
		if rerr != nil {
			err = rerr
		} else {
			fmt.Printf("%x\n", key)
		}
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: batur <version|doctor|bench|demo|serve [--bind addr] [--mock]>\n")
}

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
		if err := b.Attach("mock-1", dialer, session.TrustedRootAuth(srv.RootPub()),
			session.DeviceInfo{Platform: "web", DeviceName: "serve-mock"}); err != nil {
			return err
		}
		if err := b.Start(ctx); err != nil {
			return err
		}
		slog.Info("serve: mock fleet attached", "session", "mock-1", "data", *data)
	} else {
		return fmt.Errorf("real WhatsApp-web dialer/registration is pending (docs/TASKS.md T-101..T-103); use --mock for now")
	}
	apiSrv, err := apiserver.New(&apiserver.Server{
		Batur: b, Bind: *bind, Token: os.Getenv("BATUR_API_TOKEN"),
		MaxBodyBytes: int64(*maxBody),
	})
	if err != nil {
		return err
	}
	slog.Info("HTTP API listening", "bind", *bind, "auth", os.Getenv("BATUR_API_TOKEN") != "",
		"history", *history, "sync", *sync, "max_body_bytes", *maxBody)
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

func hexID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
