package pb

import (
	"bytes"
	"math"
	"testing"
)

func TestKnownAnswerEncodings(t *testing.T) {
	cases := []struct {
		name string
		b    *Builder
		want []byte
	}{
		{
			name: "string field 1",
			b:    NewBuilder().String(1, "test"),
			want: []byte{0x0A, 0x04, 't', 'e', 's', 't'},
		},
		{
			name: "varint field 2 value 150",
			b:    NewBuilder().Uint(2, 150),
			want: []byte{0x10, 0x96, 0x01},
		},
		{
			name: "bytes field 3",
			b:    NewBuilder().Bytes(3, []byte{0x01, 0x02}),
			want: []byte{0x1A, 0x02, 0x01, 0x02},
		},
		{
			name: "nested message",
			b:    NewBuilder().Msg(1, NewBuilder().Uint(1, 7).String(2, "hi")),
			want: []byte{0x0A, 0x06, 0x08, 0x07, 0x12, 0x02, 0x68, 0x69},
		},
		{
			name: "fixed32",
			b:    NewBuilder().Fixed32(4, 0x01020304),
			want: []byte{0x25, 0x04, 0x03, 0x02, 0x01},
		},
	}
	for _, tc := range cases {
		got := tc.b.Build()
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: got %X want %X", tc.name, got, tc.want)
		}
	}
}

func TestNestedHandshakeShape(t *testing.T) {
	// HandshakeMessage{ClientHello{ephemeral}} shape.
	inner := NewBuilder().Bytes(1, []byte{0xAA, 0xBB})
	outer := NewBuilder().Msg(1, inner).Build()
	msg, err := Parse(outer)
	if err != nil {
		t.Fatal(err)
	}
	hello, ok := msg.GetMsg(1)
	if !ok {
		t.Fatal("missing nested hello")
	}
	eph, ok := hello.GetBytes(1)
	if !ok || !bytes.Equal(eph, []byte{0xAA, 0xBB}) {
		t.Fatalf("ephemeral = %X", eph)
	}
}

func TestScalars(t *testing.T) {
	b := NewBuilder().
		Bool(1, true).
		Sint64(2, -3).
		Int(3, -9).
		Float(4, 3.5).
		Double(5, -1.25).
		Enum(6, 2)
	msg, err := Parse(b.Build())
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := msg.GetBool(1); !ok || !v {
		t.Fatal("bool")
	}
	if v, ok := msg.GetSint64(2); !ok || v != -3 {
		t.Fatalf("sint64 = %d", v)
	}
	if v, ok := msg.GetInt(3); !ok || v != -9 {
		t.Fatalf("int = %d", v)
	}
	f, _ := msg.Get(4)
	if math.Float32frombits(f.F32) != 3.5 {
		t.Fatal("float")
	}
	d, _ := msg.Get(5)
	if math.Float64frombits(d.F64) != -1.25 {
		t.Fatal("double")
	}
	if v, ok := msg.GetInt(6); !ok || v != 2 {
		t.Fatal("enum")
	}
}

func TestZigzagVectors(t *testing.T) {
	pairs := []struct {
		in  int64
		out uint64
	}{
		{0, 0}, {-1, 1}, {1, 2}, {-2, 3},
		{math.MaxInt64, uint64(math.MaxInt64) << 1},
		{math.MinInt64, uint64(math.MaxInt64)<<1 | 1},
	}
	for _, p := range pairs {
		if got := ZigEncode(p.in); got != p.out {
			t.Errorf("zig(%d) = %d want %d", p.in, got, p.out)
		}
		if back := ZigDecode(p.out); back != p.in {
			t.Errorf("unzig(%d) = %d want %d", p.out, back, p.in)
		}
	}
}

func TestMalformed(t *testing.T) {
	bad := [][]byte{
		{0xFF},                 // key varint truncated
		{0x0A, 0x05, 'a', 'b'}, // bytes length overruns
		{0x0D, 0x01},           // fixed32 truncated
		{0x07},                 // wire type 7 unsupported
		{0x08, 0xFF, 0xFF},     // varint field truncated
	}
	for _, data := range bad {
		if _, err := Parse(data); err == nil {
			t.Errorf("expected error parsing %X", data)
		}
	}
}
