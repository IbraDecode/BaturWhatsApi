package binary

import (
	"bytes"
	"compress/zlib"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ibradecode/baturwhatsapi/protocol/token"
)

func dict() *token.Dictionary { return token.Default() }

func mustDecode(t *testing.T, payload []byte) Node {
	t.Helper()
	n, err := DecodeDefault(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return n
}

func roundTrip(t *testing.T, n Node) Node {
	t.Helper()
	wire := Marshal(n)
	if wire == nil {
		t.Fatalf("marshal returned nil")
	}
	out := mustDecode(t, wire)
	return out
}

func TestRoundTripSimple(t *testing.T) {
	in := NewNode("iq", Attrs{"id": "ABC123", "type": "set", "to": "s.whatsapp.net"},
		Node{Tag: "response", Attrs: Attrs{"ack": "0"}, Content: "hello world"})
	out := roundTrip(t, in)
	if out.Tag != "iq" {
		t.Fatalf("tag = %q", out.Tag)
	}
	if out.MustStringAttr("id") != "ABC123" {
		t.Fatalf("id = %q", out.MustStringAttr("id"))
	}
	if out.MustStringAttr("type") != "set" {
		t.Fatalf("type attr = %q", out.MustStringAttr("type"))
	}
	kids := out.Children()
	if len(kids) != 1 || kids[0].Tag != "response" {
		t.Fatalf("children = %+v", out.Content)
	}
	if s, ok := kids[0].Content.(string); !ok || s != "hello world" {
		t.Fatalf("content = %#v", kids[0].Content)
	}
}

func TestRoundTripAllStringFlavors(t *testing.T) {
	// dictionary single, dictionary double, nibble-packed, hex-packed, raw.
	cases := []string{
		"message",           // single token
		"s.whatsapp.net",    // single token
		"read-self",         // double token dict0
		"w:g2",              // double token
		"12-34.56",          // nibble packable
		"0123456789ABCDEF",  // hex packable (also nibble? no: A-F not nibble)
		"9",                 // nibble packable single char
		"héllo ✨ unicode 🚀", // raw utf8
		strings.Repeat("x", 300),
	}
	for _, s := range cases {
		in := NewNode("iq", Attrs{"v": s})
		out := roundTrip(t, in)
		if got := out.MustStringAttr("v"); got != s {
			t.Errorf("string flavor %q -> %q", s, got)
		}
	}
}

func TestBinaryContentStaysBytesWhenNotUTF8(t *testing.T) {
	blob := []byte{0x00, 0x80, 0xFF, 0xFE, 0x01}
	in := NewBinaryNode("enc", blob)
	out := roundTrip(t, in)
	got, ok := out.Content.([]byte)
	if !ok || !bytes.Equal(got, blob) {
		t.Fatalf("content = %#v", out.Content)
	}
}

func TestLargeBinaryUsesExtendedLengths(t *testing.T) {
	// 300 bytes -> Binary8? >255 so Binary20; and a >65535 case for list16.
	blob := make([]byte, 300)
	for i := range blob {
		blob[i] = byte(i)
	}
	out := roundTrip(t, NewBinaryNode("data", blob))
	got := out.Content.([]byte)
	if !bytes.Equal(got, blob) {
		t.Fatalf("binary20 roundtrip mismatch")
	}

	big := make([]byte, 70000)
	for i := range big {
		big[i] = byte(i * 7)
	}
	out2 := roundTrip(t, NewBinaryNode("data", big))
	if g := out2.Content.([]byte); !bytes.Equal(g, big) {
		t.Fatalf("binary32 roundtrip mismatch")
	}
}

func TestJIDFlavors(t *testing.T) {
	jids := []JID{
		NewJID("628123456789", ServerUser),
		{User: "628123456789", Device: 3, Server: ServerUser}, // ADJID
		NewJID("", ServerGroup),
		NewJID("1234567", ServerGroup),
		NewJID("status", ServerBroadcast),
		{User: "123", Device: 2, Integrator: 7, Server: ServerInterop},
		{User: "999", Device: 1, Server: ServerLID}, // ADJID LID
	}
	for _, j := range jids {
		out := roundTrip(t, NewNode("x", Attrs{"to": j}))
		got, ok := out.JIDAttr("to")
		if !ok {
			t.Fatalf("jid attr missing for %v", j)
		}
		if got != j {
			t.Errorf("JID %v (%s) -> %v (%s)", j, j, got, got)
		}
	}
}

func TestNullNodeQuirk(t *testing.T) {
	out := roundTrip(t, Node{Tag: "0"})
	if out.Tag != "0" {
		t.Fatalf("null node tag = %q", out.Tag)
	}
}

func TestEmptyContentVsNoContent(t *testing.T) {
	noContent := NewNode("pong", nil)
	out := roundTrip(t, noContent)
	if out.Content != nil {
		t.Fatalf("expected nil content, got %#v", out.Content)
	}
}

func TestIntAndBoolAttrs(t *testing.T) {
	in := NewNode("n", Attrs{"count": 42, "ok": true, "big": int64(9007199254740991)})
	out := roundTrip(t, in)
	if out.MustStringAttr("count") != "42" || out.MustStringAttr("ok") != "true" ||
		out.MustStringAttr("big") != "9007199254740991" {
		t.Fatalf("numeric attrs: %+v", out.Attrs)
	}
}

func TestZlibPayload(t *testing.T) {
	// Simulate a server response with zlib-compressed stream (flag byte 0x02).
	var raw bytes.Buffer
	zw := zlib.NewWriter(&raw)
	stream, err := Encode(NewNode("iq", Attrs{"id": "z"}), dict())
	if err != nil {
		t.Fatal(err)
	}
	// whatsmeow's Unpack treats flag&2 as zlib; compressed body starts right after flag.
	_ = stream
	_, _ = zw.Write(stream)
	zw.Close()
	payload := append([]byte{0x02}, raw.Bytes()...)
	n, err := DecodeDefault(payload)
	if err != nil {
		t.Fatalf("zlib decode: %v", err)
	}
	if n.Tag != "iq" || n.MustStringAttr("id") != "z" {
		t.Fatalf("bad node from zlib payload: %+v", n)
	}
}

func TestTruncatedStreams(t *testing.T) {
	full := Marshal(Node{Tag: "iq", Attrs: Attrs{"a": "bcdef", "to": NewJID("123", ServerUser)}, Content: []Node{NewTextNode("child", "text"), NewNode("empty", nil)}})
	for cut := 1; cut < len(full); cut++ {
		if _, err := DecodeDefault(full[:cut]); err == nil {
			t.Fatalf("expected error for truncated payload at %d", cut)
		}
	}
}

func TestTrailingGarbage(t *testing.T) {
	full := Marshal(NewNode("iq", nil))
	if _, err := DecodeDefault(append(full, 0x11, 0x22)); err == nil {
		t.Fatal("expected trailing data error")
	}
}

func randomNode(r *rand.Rand, depth int) Node {
	tags := []string{"iq", "message", "node", "response", "contact", "mytag-" + string(rune('a'+r.Intn(26))), "12-34", "ABCD1234"}
	n := Node{Tag: tags[r.Intn(len(tags))], Attrs: Attrs{}}
	for i := 0; i < r.Intn(4); i++ {
		k := tags[r.Intn(len(tags))]
		if n.Attrs[k] != nil {
			continue
		}
		switch r.Intn(6) {
		case 0:
			n.Attrs[k] = r.Intn(100000)
		case 1:
			n.Attrs[k] = "62812" + string(rune('0'+r.Intn(9))) + "@s.whatsapp.net"
		case 2:
			n.Attrs[k] = []byte{byte(r.Intn(256)), byte(r.Intn(256))}
		case 3:
			n.Attrs[k] = NewJID("12345", ServerUser)
		case 4:
			n.Attrs[k] = strings.Repeat("u", 1+r.Intn(399))
		case 5:
			n.Attrs[k] = true
		}
	}
	if depth < 3 && r.Intn(3) == 0 {
		n.Content = []Node{randomNode(r, depth+1), randomNode(r, depth+1)}
	} else if r.Intn(2) == 0 {
		n.Content = "content-" + tags[r.Intn(len(tags))]
	}
	return n
}

func TestFuzzRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 500; i++ {
		in := randomNode(r, 0)
		wire := Marshal(in)
		if wire == nil {
			t.Fatalf("marshal nil for %+v", in)
		}
		out, err := DecodeDefault(wire)
		if err != nil {
			t.Fatalf("iter %d decode %+v: %v", i, in, err)
		}
		if out.Tag != in.Tag {
			t.Fatalf("iter %d tag %q != %q", i, out.Tag, in.Tag)
		}
		if !reflect.DeepEqual(canonicalAttrs(in.Attrs), canonicalAttrs(out.Attrs)) {
			t.Fatalf("iter %d attrs in=%v out=%v", i, in.Attrs, out.Attrs)
		}
	}
}

// canonicalAttrs maps every attribute value to the string form the wire
// round-trip preserves.
func canonicalAttrs(a Attrs) Attrs {
	out := Attrs{}
	for k, v := range a {
		switch typed := v.(type) {
		case int:
			out[k] = strconv.Itoa(typed)
		case bool:
			out[k] = strconv.FormatBool(typed)
		case []byte:
			if utf8.Valid(typed) {
				out[k] = string(typed)
			} else {
				out[k] = typed
			}
		default:
			out[k] = typed
		}
	}
	return out
}
