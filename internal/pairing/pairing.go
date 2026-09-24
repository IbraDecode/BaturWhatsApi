// Package pairing implements the companion-device pairing flow used by
// BaturWhatsApi: Noise XX handshake, a pair-device IQ, a QR challenge, then
// credentials after the phone scans the code.
//
// The wire shape is the engine's own mock protocol (internal/mockserver),
// not a claim of byte-for-byte WhatsApp companion registration. Live
// WhatsApp pairing remains blocked on a real device (T-103 / T-102).
package pairing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ibradecode/baturwhatsapi/internal/wapb"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/protocol/pb"
	"github.com/ibradecode/baturwhatsapi/protocol/token"
	"github.com/ibradecode/baturwhatsapi/security/noise"
	"github.com/ibradecode/baturwhatsapi/transport"
)

// Errors returned by Pair.
var (
	ErrPairingTimeout   = errors.New("pairing: QR scan timeout")
	ErrPairingCancelled = errors.New("pairing: cancelled")
	ErrPairingFailed    = errors.New("pairing: server rejected")
	ErrNoDialer         = errors.New("pairing: dialer required")
)

// PairingResult contains the credentials received after a successful scan.
// Noise keys are X25519. NoiseKeySeed is the 32-byte private key.
type PairingResult struct {
	AccountJID     string    `json:"account_jid"`
	DeviceID       string    `json:"device_id"`
	NoiseKeySeed   []byte    `json:"noise_key_seed"`
	ServerStatic   []byte    `json:"server_static"`
	CertChain      []byte    `json:"cert_chain"`
	RegistrationID uint32    `json:"reg_id"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// PairingConfig configures one pairing attempt.
type PairingConfig struct {
	// EdgeServer is the WebSocket URL. Default: wss://web.whatsapp.com/ws.
	EdgeServer string

	DeviceID   string
	DeviceName string
	Platform   string

	Logger *slog.Logger
	Dialer transport.Dialer

	// ServerAuth verifies (serverStatic, certPayload) after ServerHello.
	// Nil refuses the handshake (fail-closed).
	ServerAuth func(static, payload []byte) error

	// QRCallback is invoked when the QR challenge arrives.
	// Returning an error cancels pairing.
	QRCallback func(code, ref string, expiresAt time.Time) error

	// QRTimeout bounds the whole scan wait (default 60s).
	QRTimeout time.Duration

	// Dict is the binary dictionary. Nil uses token.Default().
	Dict *token.Dictionary
}

// Pair runs the pairing flow and returns credentials on success.
func Pair(ctx context.Context, cfg PairingConfig) (*PairingResult, error) {
	if cfg.Dialer == nil {
		return nil, ErrNoDialer
	}
	if cfg.EdgeServer == "" {
		cfg.EdgeServer = "wss://web.whatsapp.com/ws"
	}
	if cfg.QRTimeout == 0 {
		cfg.QRTimeout = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default().With("comp", "pairing")
	}
	if cfg.Dict == nil {
		cfg.Dict = token.Default()
	}
	if cfg.ServerAuth == nil {
		return nil, errors.New("pairing: ServerAuth policy required")
	}
	if cfg.DeviceID == "" {
		id, err := randomID()
		if err != nil {
			return nil, err
		}
		cfg.DeviceID = id
	}

	noiseKP, err := noise.NewKeyPair()
	if err != nil {
		return nil, fmt.Errorf("pairing: noise keypair: %w", err)
	}

	conn, err := cfg.Dialer.Dial(ctx, cfg.EdgeServer)
	if err != nil {
		return nil, fmt.Errorf("pairing: dial %s: %w", cfg.EdgeServer, err)
	}
	defer conn.Close()

	payload := buildFinishPayload(cfg, noiseKP.Public())
	if liveConn(conn) {
		payload = liveClientPayload()
	}
	hs, err := handshake(ctx, conn, noiseKP, cfg.ServerAuth, payload)
	if err != nil {
		return nil, err
	}

	sendNode := func(n binary.Node) error {
		plain := binary.MarshalDict(n, cfg.Dict)
		return conn.SendBinary(ctx, hs.send.Seal(nil, plain))
	}

	id := requestID()
	if err := sendNode(binary.Node{
		Tag: "iq",
		Attrs: binary.Attrs{
			"id": id, "type": "get", "xmlns": "batur.pair",
			"to": "s.whatsapp.net",
		},
		Content: []binary.Node{{
			Tag: "pair-device",
			Attrs: binary.Attrs{
				"device_id":   cfg.DeviceID,
				"device_name": cfg.DeviceName,
				"platform":    cfg.Platform,
			},
		}},
	}); err != nil {
		return nil, fmt.Errorf("pairing: pair-device: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, cfg.QRTimeout)
	defer cancel()

	code, ref, expiresAt, err := waitForQR(waitCtx, conn, hs.recv, cfg.Dict)
	if err != nil {
		return nil, err
	}
	if cfg.QRCallback != nil {
		if err := cfg.QRCallback(code, ref, expiresAt); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPairingCancelled, err)
		}
	}

	result, err := waitForCredentials(waitCtx, conn, hs.recv, cfg.Dict)
	if err != nil {
		return nil, err
	}
	if len(result.NoiseKeySeed) != 32 {
		result.NoiseKeySeed = noiseKP.Seed()
	}
	if len(result.ServerStatic) != 32 {
		result.ServerStatic = append([]byte(nil), hs.serverStatic...)
	}
	if result.DeviceID == "" {
		result.DeviceID = cfg.DeviceID
	}
	cfg.Logger.Info("pairing successful", "account", result.AccountJID, "device", result.DeviceID)
	return result, nil
}

// clientHelloFrame builds the opening handshake. The mock uses the
// engine's historical field 1; live WhatsApp Web uses field 2.
func clientHelloFrame(live bool, ephemeral []byte) []byte {
	inner := (&wapb.ClientHello{Ephemeral: ephemeral}).Build()
	field := uint32(wapb.HSFieldClientHello)
	if live {
		field = 2
	}
	return wapb.WrapTop(field, inner)
}

func unwrapHello(data []byte, live bool) (pb.Message, error) {
	field := uint32(wapb.HSFieldServerHello)
	if live {
		field = 3
	}
	return wapb.UnwrapTop(data, field)
}

// prologue is the extra Noise prologue. The mock shares a synthetic
// binding header; the live socket uses the pattern alone (nil).
func prologue(conn transport.Conn) []byte {
	h := conn.BindingHeader()
	if len(h) >= 4 && string(h[:4]) == "GET " {
		return nil
	}
	return h
}

type hsResult struct {
	send         *noise.Cipher
	recv         *noise.Cipher
	serverStatic []byte
}

func handshake(ctx context.Context, conn transport.Conn, staticKP *noise.KeyPair, serverAuth func(static, payload []byte) error, finishPayload []byte) (*hsResult, error) {
	pro := prologue(conn)
	live := len(conn.BindingHeader()) >= 4 && string(conn.BindingHeader()[:4]) == "GET "
	if live {
		pro = []byte{'W', 'A', 6, 3}
	}
	xx, err := noise.NewXXClient(staticKP, pro)
	if err != nil {
		return nil, err
	}
	ephC, err := xx.ClientHello1()
	if err != nil {
		return nil, err
	}
	hello := clientHelloFrame(live, ephC)
	if err := conn.SendBinary(ctx, hello); err != nil {
		return nil, err
	}
	resp, err := recvTimeout(ctx, conn, 20*time.Second)
	if err != nil {
		return nil, fmt.Errorf("pairing: server hello: %w", err)
	}
	if live && len(resp) >= 3 && resp[0] == 0 && resp[1] == 1 {
		resp = resp[3:]
	}
	shMsg, err := unwrapHello(resp, live)
	if err != nil || shMsg == nil {
		n := len(resp)
		if n > 48 {
			n = 48
		}
		return nil, fmt.Errorf("pairing: missing server hello (%d bytes, head %x)", len(resp), resp[:n])
	}
	sh, err := wapb.ParseServerHello(shMsg)
	if err != nil || len(sh.Ephemeral) != 32 || len(sh.Static) == 0 {
		return nil, fmt.Errorf("pairing: malformed server hello")
	}
	serverStatic, serverPayload, err := xx.ReadServerHello(sh.Ephemeral, sh.Static, sh.Payload)
	if err != nil {
		return nil, fmt.Errorf("pairing: server hello rejected: %w", err)
	}
	if err := serverAuth(serverStatic, serverPayload); err != nil {
		return nil, fmt.Errorf("pairing: server auth: %w", err)
	}
	clientStaticCT, clientPayloadCT, err := xx.WriteClientFinish(finishPayload)
	if err != nil {
		return nil, err
	}
	finishField := uint32(wapb.HSFieldClientFinish)
	if live {
		finishField = 4
	}
	finish := wapb.WrapTop(finishField, (&wapb.ClientFinish{Static: clientStaticCT, Payload: clientPayloadCT}).Build())
	if err := conn.SendBinary(ctx, finish); err != nil {
		return nil, err
	}
	send, recv, err := xx.SendCipher()
	if err != nil {
		return nil, err
	}
	return &hsResult{send: send, recv: recv, serverStatic: serverStatic}, nil
}

// liveClientPayload is the minimal ClientPayload WhatsApp Web accepts
// before it will emit a pairing QR. Field numbers follow the public
// WAWeb protobuf schema (userAgent=5, webInfo=6, connectReason=13).
func liveClientPayload() []byte {
	app := pb.NewBuilder().Uint(1, 2).Uint(2, 3000).Uint(3, 1048321180).Build()
	ua := pb.NewBuilder().
		Uint(1, 14).
		Bytes(2, app).
		Bytes(3, []byte("000")).
		Bytes(4, []byte("000")).
		Bytes(5, []byte("0.1.0")).
		Bytes(7, []byte("Desktop")).
		Bytes(8, []byte("0.1.0")).
		Uint(10, 0).
		Bytes(11, []byte("en")).
		Bytes(12, []byte("US")).
		Build()
	web := pb.NewBuilder().Uint(4, 0).Build()
	return pb.NewBuilder().
		Bool(3, false).
		Bytes(5, ua).
		Bytes(6, web).
		Uint(12, 1).
		Uint(13, 1).
		Build()
}

func liveConn(conn transport.Conn) bool {
	h := conn.BindingHeader()
	return len(h) >= 4 && string(h[:4]) == "GET "
}

func buildFinishPayload(cfg PairingConfig, noisePub []byte) []byte {
	blob, _ := json.Marshal(map[string]any{
		"device_id": cfg.DeviceID,
		"name":      cfg.DeviceName,
		"platform":  cfg.Platform,
		"noise_pub": base64.StdEncoding.EncodeToString(noisePub),
	})
	return blob
}

func waitForQR(ctx context.Context, conn transport.Conn, recv *noise.Cipher, dict *token.Dictionary) (code, ref string, expiresAt time.Time, err error) {
	for {
		node, err := nextNode(ctx, conn, recv, dict)
		if err != nil {
			if ctx.Err() != nil {
				return "", "", time.Time{}, ErrPairingTimeout
			}
			return "", "", time.Time{}, err
		}
		child, ok := findIQChild(node, "pair-device")
		if !ok {
			continue
		}
		code = child.MustStringAttr("code")
		ref = child.MustStringAttr("ref")
		if expStr := child.MustStringAttr("expires_at"); expStr != "" {
			if exp, perr := time.Parse(time.RFC3339, expStr); perr == nil {
				expiresAt = exp
			}
		}
		if code != "" && ref != "" {
			return code, ref, expiresAt, nil
		}
	}
}

func waitForCredentials(ctx context.Context, conn transport.Conn, recv *noise.Cipher, dict *token.Dictionary) (*PairingResult, error) {
	for {
		node, err := nextNode(ctx, conn, recv, dict)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ErrPairingTimeout
			}
			return nil, err
		}
		if _, ok := findIQChild(node, "error"); ok {
			return nil, ErrPairingFailed
		}
		child, ok := findIQChild(node, "pair-success")
		if !ok {
			continue
		}
		return parsePairSuccess(child)
	}
}

func findIQChild(node binary.Node, tag string) (binary.Node, bool) {
	if node.Tag != "iq" || node.MustStringAttr("type") != "result" {
		return binary.Node{}, false
	}
	return node.ChildByTag(tag)
}

func nextNode(ctx context.Context, conn transport.Conn, recv *noise.Cipher, dict *token.Dictionary) (binary.Node, error) {
	raw, err := conn.ReceiveBinary(ctx)
	if err != nil {
		return binary.Node{}, fmt.Errorf("pairing: receive: %w", err)
	}
	if len(raw) <= 8 && len(raw) >= 3 && raw[0] == 0x88 {
		return binary.Node{}, fmt.Errorf("pairing: server refused handshake (%x)", raw)
	}
	plain, err := recv.Open(nil, raw)
	if err != nil {
		n := len(raw)
		if n > 24 {
			n = 24
		}
		return binary.Node{}, fmt.Errorf("pairing: decrypt (%d bytes, head %x): %w", len(raw), raw[:n], err)
	}
	node, err := binary.Decode(dict, plain)
	if err != nil {
		return binary.Node{}, fmt.Errorf("pairing: decode: %w", err)
	}
	return node, nil
}

func parsePairSuccess(node binary.Node) (*PairingResult, error) {
	result := &PairingResult{
		AccountJID: node.MustStringAttr("account_jid"),
		DeviceID:   node.MustStringAttr("device_id"),
	}
	if b, err := base64.StdEncoding.DecodeString(node.MustStringAttr("noise_key_seed")); err == nil && len(b) == 32 {
		result.NoiseKeySeed = b
	}
	if b, err := base64.StdEncoding.DecodeString(node.MustStringAttr("server_static")); err == nil && len(b) == 32 {
		result.ServerStatic = b
	}
	if b, err := base64.StdEncoding.DecodeString(node.MustStringAttr("cert_chain")); err == nil {
		result.CertChain = b
	}
	if reg := node.MustStringAttr("reg_id"); reg != "" {
		fmt.Sscanf(reg, "%d", &result.RegistrationID)
	}
	if exp := node.MustStringAttr("expires_at"); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			result.ExpiresAt = t
		}
	}
	if result.AccountJID == "" {
		return nil, fmt.Errorf("%w: missing account", ErrPairingFailed)
	}
	return result, nil
}

func recvTimeout(ctx context.Context, conn transport.Conn, d time.Duration) ([]byte, error) {
	tctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return conn.ReceiveBinary(tctx)
}

func requestID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("batur-%x", b), nil
}
