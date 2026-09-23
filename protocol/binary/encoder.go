package binary

import (
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/ibradecode/baturwhatsapi/protocol/token"
)

// Encoder serializes nodes into the WAWebMulti node stream using a token
// dictionary. The zero value is not usable; call NewEncoder.
type Encoder struct {
	dict *token.Dictionary
	buf  []byte
	err  error
}

// NewEncoder creates an encoder writing into a fresh stream.
func NewEncoder(dict *token.Dictionary) *Encoder {
	return &Encoder{dict: dict}
}

func (e *Encoder) push(b ...byte) {
	if e.err != nil {
		return
	}
	e.buf = append(e.buf, b...)
}

func (e *Encoder) fail(format string, args ...any) {
	if e.err == nil {
		e.err = fmt.Errorf(format, args...)
	}
}

// Bytes returns the encoded stream so far.
func (e *Encoder) Bytes() []byte { return e.buf }

// Err returns the first error encountered.
func (e *Encoder) Err() error { return e.err }

// WriteNode appends one node to the stream.
func (e *Encoder) WriteNode(n Node) {
	if e.err != nil {
		return
	}
	if n.Tag == "0" {
		// Legacy null-node quirk preserved for wire compatibility.
		e.push(token.List8, token.ListEmpty)
		return
	}
	hasContent := 0
	if n.Content != nil {
		hasContent = 1
	}
	attrs := n.countableAttrs()
	e.writeListStart(2*len(attrs) + 1 + hasContent)
	e.writeString(n.Tag)
	for _, kv := range attrs {
		e.writeString(kv.key)
		e.write(kv.val)
	}
	if hasContent == 1 {
		e.write(n.Content)
	}
}

type attrKV struct {
	key string
	val any
}

// countableAttrs returns attributes sorted by key, dropping empty values.
// Sorted output keeps streams byte-deterministic, which the engine relies on
// for golden tests and replayable fixtures.
func (n Node) countableAttrs() []attrKV {
	out := make([]attrKV, 0, len(n.Attrs))
	for k, v := range n.Attrs {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		out = append(out, attrKV{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// WriteListStart appends a list header for the given size.
func (e *Encoder) writeListStart(size int) {
	switch {
	case size == 0:
		e.push(token.ListEmpty)
	case size < 256:
		e.push(token.List8, byte(size))
	case size < math.MaxUint16:
		e.push(token.List16, byte(size>>8), byte(size))
	default:
		e.fail("binary: list too large: %d", size)
	}
}

func (e *Encoder) write(data any) {
	switch typed := data.(type) {
	case nil:
		e.push(token.ListEmpty)
	case Node:
		e.WriteNode(typed)
	case []Node:
		e.writeListStart(len(typed))
		for _, child := range typed {
			e.WriteNode(child)
		}
	case JID:
		e.writeJID(typed)
	case string:
		e.writeString(typed)
	case []byte:
		e.writeBytes(typed)
	case bool:
		e.writeString(strconv.FormatBool(typed))
	case int:
		e.writeString(strconv.Itoa(typed))
	case int32:
		e.writeString(strconv.FormatInt(int64(typed), 10))
	case int64:
		e.writeString(strconv.FormatInt(typed, 10))
	case uint:
		e.writeString(strconv.FormatUint(uint64(typed), 10))
	case uint32:
		e.writeString(strconv.FormatUint(uint64(typed), 10))
	case uint64:
		e.writeString(strconv.FormatUint(typed, 10))
	default:
		e.fail("binary: unsupported content type %T", data)
	}
}

func (e *Encoder) writeString(s string) {
	if idx, ok := e.dict.IndexOfSingle(s); ok {
		e.push(idx)
		return
	}
	if dictIdx, idx, ok := e.dict.IndexOfDouble(s); ok {
		e.push(byte(token.Dictionary0+int(dictIdx)), idx)
		return
	}
	if isNibblePackable(s) {
		e.writePacked(s, token.Nibble8, packNibble)
		return
	}
	if isHexPackable(s) {
		e.writePacked(s, token.Hex8, packHex)
		return
	}
	e.writeBytesLen(len(s))
	e.push([]byte(s)...)
}

func (e *Encoder) writeBytes(b []byte) {
	e.writeBytesLen(len(b))
	e.push(b...)
}

func (e *Encoder) writeBytesLen(n int) {
	switch {
	case n < 256:
		e.push(token.Binary8, byte(n))
	case n < 1<<20:
		e.push(token.Binary20, byte(n>>16&0x0F), byte(n>>8), byte(n))
	case int64(n) < math.MaxInt32:
		e.push(token.Binary32, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		e.fail("binary: blob too large: %d", n)
	}
}

func (e *Encoder) writeJID(j JID) {
	switch {
	case j.isADJIDEncodable():
		e.push(token.ADJID, j.ActualAgent(), byte(j.Device&0xFF))
		e.writeString(j.User)
	case j.Server == ServerMSGram:
		e.push(token.FBJID)
		e.write(j.User)
		e.push(byte(j.Device>>8), byte(j.Device))
		e.write(j.Server)
	case j.Server == ServerInterop:
		e.push(token.InteropJID)
		e.write(j.User)
		e.push(byte(j.Device>>8), byte(j.Device))
		e.push(byte(j.Integrator>>8), byte(j.Integrator))
		e.write(j.Server)
	default:
		e.push(token.JIDPair)
		if j.User == "" {
			e.push(token.ListEmpty)
		} else {
			e.write(j.User)
		}
		e.write(j.Server)
	}
}

func (e *Encoder) writePacked(s string, tag byte, pack func(byte) byte) {
	e.push(tag)
	round := byte((len(s) + 1) / 2)
	if len(s)%2 != 0 {
		round |= 0x80
	}
	e.push(round)
	for i := 0; i+1 < len(s); i += 2 {
		e.push(pack(s[i])<<4 | pack(s[i+1]))
	}
	if len(s)%2 != 0 {
		e.push(pack(s[len(s)-1]) << 4)
	}
}

func isNibblePackable(s string) bool {
	if len(s) == 0 || len(s) > token.PackedMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func packNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c == '-':
		return 10
	case c == '.':
		return 11
	default:
		return 15
	}
}

func isHexPackable(s string) bool {
	if len(s) == 0 || len(s) > token.PackedMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func packHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return 10 + (c - 'A')
	default:
		return 15
	}
}

// Encode serializes a node tree into a raw node stream (no flag byte).
func Encode(n Node, dict *token.Dictionary) ([]byte, error) {
	enc := NewEncoder(dict)
	enc.WriteNode(n)
	if enc.Err() != nil {
		return nil, enc.Err()
	}
	return enc.Bytes(), nil
}

// Marshal encodes a top-level node into a wire payload (leading flag byte
// marks an uncompressed stream).
func Marshal(n Node) []byte {
	return MarshalDict(n, token.Default())
}

// MarshalDict encodes with an explicit dictionary.
func MarshalDict(n Node, dict *token.Dictionary) []byte {
	stream, err := Encode(n, dict)
	if err != nil {
		return nil
	}
	return append([]byte{streamFlagRaw}, stream...)
}
