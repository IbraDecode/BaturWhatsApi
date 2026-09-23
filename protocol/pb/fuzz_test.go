package pb

import (
	"testing"
)

// FuzzParse — the protobuf wire parser must never panic on arbitrary bytes
// and must never return a nil-message-with-nil-error.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x01, 0x10, 0x02})             // two varints, field 1 & 2
	f.Add([]byte{0x0a, 0x03, 'a', 'b', 'c'})          // length-delimited
	f.Add([]byte{0x0a, 0x7f})                         // truncated length
	f.Add([]byte{0x08, 0xff, 0xff, 0xff, 0xff, 0x01}) // 5-byte varint
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil && m != nil {
			t.Fatalf("error %v with non-nil message %+v", err, m)
		}
	})
}
