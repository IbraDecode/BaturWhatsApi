// Package pb implements the subset of the protobuf wire format needed by
// BaturWhatsApi's protocol engine without pulling a full protobuf runtime
// into the core: varint/zigzag scalars, length-delimited fields and nested
// messages.
//
// The engine deliberately avoids schema code generation at this layer; typed
// accessors live next to the protocol subsystems that own each message.
package pb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Wire types.
const (
	VarintType = 0
	Fixed64    = 1
	Bytes      = 2
	Fixed32    = 5
)

// ErrMalformed signals an invalid wire encoding.
var ErrMalformed = errors.New("pb: malformed message")

// Field is one encoded protobuf field.
type Field struct {
	Num  uint32
	Type uint32
	// Exactly one of the payloads below is meaningful, chosen by Type:
	// Varint -> V (covers bool/int32/int64/enum; sint uses zigzag decoded),
	// Bytes -> B, Fixed32 -> F32, Fixed64 -> F64.
	V   uint64
	B   []byte
	F32 uint32
	F64 uint64
}

// Message is an ordered list of fields.
type Message []Field

// Builder accumulates fields in order.
type Builder struct {
	fields []Field
}

// NewBuilder starts an empty message builder.
func NewBuilder() *Builder { return &Builder{} }

func (b *Builder) add(f Field) *Builder {
	b.fields = append(b.fields, f)
	return b
}

// Varint appends a varint field.
func (b *Builder) Varint(num uint32, v uint64) *Builder {
	return b.add(Field{Num: num, Type: VarintType, V: v})
}

// Int appends a signed int field (standard two's complement varint).
func (b *Builder) Int(num uint32, v int64) *Builder {
	return b.Varint(num, uint64(v))
}

// Uint appends an unsigned varint field.
func (b *Builder) Uint(num uint32, v uint64) *Builder {
	return b.Varint(num, v)
}

// Bool appends a boolean field.
func (b *Builder) Bool(num uint32, v bool) *Builder {
	if v {
		return b.Varint(num, 1)
	}
	return b.Varint(num, 0)
}

// Enum appends an enum field.
func (b *Builder) Enum(num uint32, v int32) *Builder {
	return b.add(Field{Num: num, Type: VarintType, V: uint64(int64(v))})
}

// Sint32 appends a zigzag-encoded signed int32.
func (b *Builder) Sint32(num uint32, v int32) *Builder {
	return b.add(Field{Num: num, Type: VarintType, V: uint64(ZigEncode32(v))})
}

// Sint64 appends a zigzag-encoded signed int64.
func (b *Builder) Sint64(num uint32, v int64) *Builder {
	return b.add(Field{Num: num, Type: VarintType, V: ZigEncode(v)})
}

// Bytes appends a length-delimited byte field.
func (b *Builder) Bytes(num uint32, data []byte) *Builder {
	return b.add(Field{Num: num, Type: Bytes, B: data})
}

// String appends a length-delimited string field.
func (b *Builder) String(num uint32, s string) *Builder {
	return b.Bytes(num, []byte(s))
}

// Msg appends a nested message.
func (b *Builder) Msg(num uint32, m *Builder) *Builder {
	return b.Bytes(num, m.Build())
}

// Fixed32 appends a 32-bit fixed field.
func (b *Builder) Fixed32(num uint32, v uint32) *Builder {
	return b.add(Field{Num: num, Type: Fixed32, F32: v})
}

// Float appends a float32 field.
func (b *Builder) Float(num uint32, v float32) *Builder {
	return b.Fixed32(num, math.Float32bits(v))
}

// Fixed64 appends a 64-bit fixed field.
func (b *Builder) Fixed64(num uint32, v uint64) *Builder {
	return b.add(Field{Num: num, Type: Fixed64, F64: v})
}

// Double appends a float64 field.
func (b *Builder) Double(num uint32, v float64) *Builder {
	return b.Fixed64(num, math.Float64bits(v))
}

// Build encodes the message.
func (b *Builder) Build() []byte {
	var out []byte
	for _, f := range b.fields {
		out = f.AppendTo(out)
	}
	return out
}

// AppendTo serializes the field onto dst.
func (f Field) AppendTo(dst []byte) []byte {
	key := f.Num<<3 | f.Type
	dst = AppendVarint(dst, uint64(key))
	switch f.Type {
	case VarintType:
		dst = AppendVarint(dst, f.V)
	case Bytes:
		dst = AppendVarint(dst, uint64(len(f.B)))
		dst = append(dst, f.B...)
	case Fixed32:
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], f.F32)
		dst = append(dst, tmp[:]...)
	case Fixed64:
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], f.F64)
		dst = append(dst, tmp[:]...)
	}
	return dst
}

// Parse decodes a message from its wire representation.
func Parse(data []byte) (Message, error) {
	var msg Message
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, fmt.Errorf("%w: bad field key", ErrMalformed)
		}
		data = data[n:]
		f := Field{Num: uint32(key >> 3), Type: uint32(key & 7)}
		switch f.Type {
		case VarintType:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, fmt.Errorf("%w: bad varint for field %d", ErrMalformed, f.Num)
			}
			data = data[n:]
			f.V = v
		case Bytes:
			l, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, fmt.Errorf("%w: bad length for field %d", ErrMalformed, f.Num)
			}
			data = data[n:]
			if l > uint64(len(data)) {
				return nil, fmt.Errorf("%w: truncated bytes field %d", ErrMalformed, f.Num)
			}
			f.B = data[:l]
			data = data[l:]
		case Fixed32:
			if len(data) < 4 {
				return nil, fmt.Errorf("%w: truncated fixed32 field %d", ErrMalformed, f.Num)
			}
			f.F32 = binary.LittleEndian.Uint32(data)
			data = data[4:]
		case Fixed64:
			if len(data) < 8 {
				return nil, fmt.Errorf("%w: truncated fixed64 field %d", ErrMalformed, f.Num)
			}
			f.F64 = binary.LittleEndian.Uint64(data)
			data = data[8:]
		default:
			return nil, fmt.Errorf("%w: unsupported wire type %d", ErrMalformed, f.Type)
		}
		msg = append(msg, f)
	}
	return msg, nil
}

// Get returns the first field with the given number.
func (m Message) Get(num uint32) (Field, bool) {
	for _, f := range m {
		if f.Num == num {
			return f, true
		}
	}
	return Field{}, false
}

// GetInt returns a varint field as int64.
func (m Message) GetInt(num uint32) (int64, bool) {
	f, ok := m.Get(num)
	if !ok || f.Type != VarintType {
		return 0, false
	}
	return int64(f.V), true
}

// GetUint returns a varint field as uint64.
func (m Message) GetUint(num uint32) (uint64, bool) {
	f, ok := m.Get(num)
	if !ok || f.Type != VarintType {
		return 0, false
	}
	return f.V, true
}

// GetSint64 returns a zigzag varint field.
func (m Message) GetSint64(num uint32) (int64, bool) {
	v, ok := m.GetUint(num)
	if !ok {
		return 0, false
	}
	return ZigDecode(v), true
}

// GetBool returns a varint field as bool.
func (m Message) GetBool(num uint32) (bool, bool) {
	v, ok := m.GetUint(num)
	if !ok {
		return false, false
	}
	return v != 0, true
}

// GetString returns a bytes field as string.
func (m Message) GetString(num uint32) (string, bool) {
	b, ok := m.GetBytes(num)
	if !ok {
		return "", false
	}
	return string(b), true
}

// GetBytes returns a length-delimited field.
func (m Message) GetBytes(num uint32) ([]byte, bool) {
	f, ok := m.Get(num)
	if !ok || f.Type != Bytes {
		return nil, false
	}
	return f.B, true
}

// GetMsg parses a nested message field.
func (m Message) GetMsg(num uint32) (Message, bool) {
	f, ok := m.Get(num)
	if !ok || f.Type != Bytes {
		return nil, false
	}
	nested, err := Parse(f.B)
	if err != nil {
		return nil, false
	}
	return nested, true
}

// AppendVarint encodes v onto dst.
func AppendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// ReadVarint decodes a varint, returning the value and the bytes consumed.
func ReadVarint(src []byte) (uint64, int) {
	return binary.Uvarint(src)
}

// ZigEncode maps a signed int64 to its zigzag unsigned form.
func ZigEncode(v int64) uint64 { return uint64(v)<<1 ^ uint64(v>>63) }

// ZigDecode reverses ZigEncode.
func ZigDecode(v uint64) int64 { return int64(v>>1) ^ -int64(v&1) }

// ZigEncode32 maps a signed int32 to its zigzag unsigned form.
func ZigEncode32(v int32) uint32 { return uint32(v)<<1 ^ uint32(v>>31) }

// ZigDecode32 reverses ZigEncode32.
func ZigDecode32(v uint32) int32 { return int32(v>>1) ^ -int32(v&1) }
