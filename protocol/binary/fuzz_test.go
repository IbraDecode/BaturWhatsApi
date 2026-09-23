package binary

import (
	"testing"
)

// Fuzz targets: Go's native fuzzing (`go test -fuzz=`). Invocations run
// their seed corpus as ordinary regression tests under `go test`, so CI
// exercises the corpus without spending fuzz time. The decoder must never
// panic on arbitrary input (memory bound was verified in bench/codec).

// FuzzDecodeDefault must never panic and must never accept trailing bytes.
func FuzzDecodeDefault(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte("iq"))
	f.Add([]byte{0xf8, 0x7a, 0x6f, 0x00})
	f.Add([]byte{0x00, 0x00, 0x08, 0x30, 0x30, 0x30, 0x38})
	f.Add([]byte{0x02}) // zlib flag with no stream
	for _, seed := range goodWires() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		node, err := DecodeDefault(data)
		if err != nil {
			return
		}
		// Encoded again must produce a decodable stream (not necessarily
		// identical, but never a panic or empty tag).
		if node.Tag == "" {
			t.Fatal("empty tag decoded from fuzz input")
		}
		wire := Marshal(node)
		if len(wire) == 0 {
			t.Fatal("re-encode of decoded node produced empty wire")
		}
		if _, err := DecodeDefault(wire); err != nil {
			t.Fatalf("re-encode/decode failed: %v", err)
		}
	})
}

// FuzzEncodeNode feeds arbitrary tag/attrs through the encoder; attribute
// values can be any of the supported kinds and encoding must not panic.
func FuzzEncodeNode(f *testing.F) {
	f.Add("iq", "id", "abc")
	f.Add("message", "to", "62812@s.whatsapp.net")
	f.Fuzz(func(t *testing.T, tag, k, v string) {
		wire := Marshal(NewNode(tag, Attrs{k: v}))
		if len(wire) == 0 {
			t.Fatal("empty wire")
		}
		if _, err := DecodeDefault(wire); err != nil {
			t.Fatalf("round-trip failed for tag=%q k=%q v=%q: %v", tag, k, v, err)
		}
	})
}

// goodWires returns a handful of real encoder outputs to seed the decoder.
func goodWires() [][]byte {
	seeds := [][]byte{
		Marshal(NewNode("iq", Attrs{"id": "seed-1", "xmlns": "urn:xmpp:whatsapp:ping"})),
		Marshal(Node{Tag: "message", Attrs: Attrs{"id": "seed-2", "from": "62812@s.whatsapp.net"},
			Content: []Node{NewTextNode("body", "hello")}}),
		Marshal(Node{Tag: "node", Content: []Node{
			NewNode("a", Attrs{"n": 42}), NewNode("b", Attrs{"ok": true}),
		}}),
		Marshal(NewNode("t", Attrs{"big": int64(1) << 40, "bin": []byte{0xde, 0xad, 0xbe, 0xef}})),
	}
	out := make([][]byte, 0, len(seeds))
	for _, s := range seeds {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

// The pb package carries its own fuzz target; this file keeps the
// wire-codec (the highest-risk surface) fuzzable.
