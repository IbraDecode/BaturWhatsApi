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

func doctor() error {
	fmt.Printf("go:        %s (%s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("cpus:      %d\n", runtime.NumCPU())
	fmt.Printf("goroutines: %d\n", runtime.NumGoroutine())
	dict := token.Default()
	fmt.Printf("token dict: %s\n", dict)
	start := time.Now()
	if _, err := noise.NewKeyPair(); err != nil {
		return err
	}
	fmt.Printf("x25519 keygen: %v\n", time.Since(start).Round(time.Microsecond))
	start = time.Now()
	node := binary.Node{Tag: "iq", Attrs: binary.Attrs{"id": hexID(), "type": "set"}}
	raw := binary.MarshalDict(node, dict)
	_, err := binary.Decode(dict, raw)
	fmt.Printf("codec warm: %v (%d bytes) err=%v\n", time.Since(start).Round(time.Microsecond), len(raw), err)
	start = time.Now()
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
	fmt.Printf("engine self-check: ONLINE in %v\n", time.Since(start).Round(time.Millisecond))
	if err := s.Stop(ctx); err != nil {
		return err
	}
	// e2e mini-exchange self check
	start = time.Now()
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
	fmt.Printf("e2e self-check: X3DH+DR handshake ok in %v\n", time.Since(start).Round(time.Millisecond))
	return nil
}

func bench() error {
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
	fmt.Printf("node encode: %d ops in %v (%.0f ops/s)\n", n, enc.Round(time.Millisecond), float64(n)/enc.Seconds())
	fmt.Printf("node decode: %d ops in %v (%.0f ops/s)\n", n, dec.Round(time.Millisecond), float64(n)/dec.Seconds())

	// noise handshake cost (client+server)
	start = time.Now()
	const hn = 5000
	for i := 0; i < hn; i++ {
		if _, err := noise.NewKeyPair(); err != nil {
			return err
		}
	}
	fmt.Printf("x25519 keygen: %d in %v (%.0f/s)\n", hn, time.Since(start).Round(time.Millisecond), float64(hn)*float64(time.Second)/float64(time.Since(start)))
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
	_ = fs.Parse(os.Args[2:])

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
	})
	if err != nil {
		return err
	}
	slog.Info("HTTP API listening", "bind", *bind, "auth", os.Getenv("BATUR_API_TOKEN") != "")
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
