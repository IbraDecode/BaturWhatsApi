package binary

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/ibradecode/baturwhatsapi/protocol/token"
)

// Errors returned by the codec.
var (
	ErrTruncated       = errors.New("binary: stream truncated")
	ErrInvalidToken    = errors.New("binary: invalid token index")
	ErrInvalidNode     = errors.New("binary: invalid node structure")
	ErrNonStringKey    = errors.New("binary: attribute key is not a string")
	ErrTrailingData    = errors.New("binary: trailing data after top-level node")
	ErrInvalidPacked   = errors.New("binary: invalid packed byte sequence")
	ErrUnsupportedData = errors.New("binary: unsupported stream data")
)

// Stream flag bytes in front of a serialized node stream.
const (
	streamFlagRaw   = 0x00
	streamFlagZlib  = 0x02
	streamFlagZlib2 = 0x03
)

// Decoder turns a node stream into Node values.
type Decoder struct {
	dict  *token.Dictionary
	data  []byte
	index int
}

// NewDecoder creates a decoder over an already-unpacked stream.
func NewDecoder(dict *token.Dictionary, stream []byte) *Decoder {
	return &Decoder{dict: dict, data: stream}
}

func (d *Decoder) need(n int) error {
	if d.index+n > len(d.data) || n < 0 {
		return fmt.Errorf("%w: need %d have %d", ErrTruncated, n, len(d.data)-d.index)
	}
	return nil
}

func (d *Decoder) readByte() (byte, error) {
	if err := d.need(1); err != nil {
		return 0, err
	}
	b := d.data[d.index]
	d.index++
	return b, nil
}

func (d *Decoder) readInt(n int) (int, error) {
	if err := d.need(n); err != nil {
		return 0, err
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<8 | int(d.data[d.index+i])
	}
	d.index += n
	return v, nil
}

func (d *Decoder) readRaw(n int) ([]byte, error) {
	if err := d.need(n); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, d.data[d.index:d.index+n])
	d.index += n
	return out, nil
}

func (d *Decoder) listSize(tag int) (int, error) {
	switch tag {
	case token.ListEmpty:
		return 0, nil
	case token.List8:
		return d.readInt(1)
	case token.List16:
		return d.readInt(2)
	}
	return 0, fmt.Errorf("%w: list tag %d at %d", ErrInvalidToken, tag, d.index)
}

// ReadNode decodes one node from the stream.
func (d *Decoder) ReadNode() (Node, error) {
	tag, err := d.readByte()
	if err != nil {
		return Node{}, err
	}
	if tag == token.ListEmpty {
		return Node{}, fmt.Errorf("%w: empty list where node expected at %d", ErrInvalidNode, d.index-1)
	}
	size, err := d.listSize(int(tag))
	if err != nil {
		return Node{}, err
	}
	// A "null" node: List8 + ListEmpty (legacy quirk the server can send).
	if tag == token.List8 && size == 0 {
		return Node{Tag: "0"}, nil
	}
	if size == 0 {
		return Node{}, ErrInvalidNode
	}
	rawTag, err := d.readStringLike()
	if err != nil {
		return Node{}, err
	}
	tagStr, ok := rawTag.(string)
	if !ok {
		return Node{}, fmt.Errorf("%w: node tag decoded as %T", ErrInvalidNode, rawTag)
	}
	n := Node{Tag: tagStr}
	attrCount := (size - 1) >> 1
	if attrCount > 0 {
		n.Attrs = make(Attrs, attrCount)
		for i := 0; i < attrCount; i++ {
			kRaw, err := d.readStringLike()
			if err != nil {
				return Node{}, err
			}
			key, ok := kRaw.(string)
			if !ok {
				return Node{}, fmt.Errorf("%w (%T) at %d", ErrNonStringKey, kRaw, d.index)
			}
			val, err := d.readContent(true)
			if err != nil {
				return Node{}, err
			}
			n.Attrs[key] = val
		}
	}
	if size%2 == 0 {
		content, err := d.readContent(true)
		if err != nil {
			return Node{}, err
		}
		n.Content = content
	}
	return n, nil
}

// readStringLike reads a value that must be a string (keys, tags): binary
// chunks become strings and JIDs are stringified.
func (d *Decoder) readStringLike() (any, error) {
	v, err := d.readContent(false)
	if err != nil {
		return nil, err
	}
	switch typed := v.(type) {
	case []byte:
		return string(typed), nil
	case JID:
		return typed.String(), nil
	default:
		return v, nil
	}
}

// readContent reads any value. When asString is set, binary payloads are
// returned as strings (used for node content where servers inline text).
func (d *Decoder) readContent(asString bool) (any, error) {
	tag, err := d.readByte()
	if err != nil {
		return nil, err
	}
	switch int(tag) {
	case token.ListEmpty:
		return nil, nil
	case token.List8, token.List16:
		d.index--
		return d.readList()
	case token.Binary8:
		size, err := d.readInt(1)
		if err != nil {
			return nil, err
		}
		return d.bytesOrString(size, asString)
	case token.Binary20:
		if err := d.need(3); err != nil {
			return nil, err
		}
		size := int(tag20(d.data[d.index], d.data[d.index+1], d.data[d.index+2]))
		d.index += 3
		return d.bytesOrString(size, asString)
	case token.Binary32:
		size, err := d.readInt(4)
		if err != nil {
			return nil, err
		}
		return d.bytesOrString(size, asString)
	case token.Dictionary0, token.Dictionary1, token.Dictionary2, token.Dictionary3:
		i, err := d.readByte()
		if err != nil {
			return nil, err
		}
		s, ok := d.dict.DoubleToken(int(tag)-token.Dictionary0, int(i))
		if !ok {
			return nil, fmt.Errorf("%w: double token %d/%d at %d", ErrInvalidToken, tag, i, d.index)
		}
		return s, nil
	case token.FBJID:
		return d.readFBJID()
	case token.InteropJID:
		return d.readInteropJID()
	case token.JIDPair:
		return d.readJIDPair()
	case token.ADJID:
		return d.readADJID()
	case token.Nibble8, token.Hex8:
		return d.readPacked8(tag)
	default:
		if s, ok := d.dict.SingleToken(int(tag)); ok {
			return s, nil
		}
		return nil, fmt.Errorf("%w: %d at %d", ErrInvalidToken, tag, d.index-1)
	}
}

func tag20(a, b, c byte) uint32 {
	return uint32(a&0x0F)<<16 | uint32(b)<<8 | uint32(c)
}

func (d *Decoder) bytesOrString(n int, asString bool) (any, error) {
	raw, err := d.readRaw(n)
	if err != nil {
		return nil, err
	}
	if asString && utf8.Valid(raw) {
		return string(raw), nil
	}
	return raw, nil
}

func (d *Decoder) readList() ([]Node, error) {
	tag, err := d.readByte()
	if err != nil {
		return nil, err
	}
	size, err := d.listSize(int(tag))
	if err != nil {
		return nil, err
	}
	out := make([]Node, size)
	for i := 0; i < size; i++ {
		out[i], err = d.ReadNode()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (d *Decoder) readPacked8(tag byte) (string, error) {
	head, err := d.readByte()
	if err != nil {
		return "", err
	}
	n := int(head & 0x7F)
	raw, err := d.readRaw(n)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, b := range raw {
		lo, hi := b>>4, b&0x0F
		c1, err := unpackByte(tag, lo)
		if err != nil {
			return "", err
		}
		sb.WriteByte(c1)
		c2, err := unpackByte(tag, hi)
		if err != nil {
			return "", err
		}
		sb.WriteByte(c2)
	}
	if head&0x80 != 0 {
		// Odd length: the last byte is pad.
		return sb.String()[:sb.Len()-1], nil
	}
	return sb.String(), nil
}

func unpackByte(tag, v byte) (byte, error) {
	switch int(tag) {
	case token.Nibble8:
		switch {
		case v < 10:
			return '0' + v, nil
		case v == 10:
			return '-', nil
		case v == 11:
			return '.', nil
		case v == 15:
			return 0, nil
		default:
			return 0, fmt.Errorf("%w: nibble %d", ErrInvalidPacked, v)
		}
	case token.Hex8:
		switch {
		case v < 10:
			return '0' + v, nil
		case v < 16:
			return 'A' + (v - 10), nil
		default:
			return 0, fmt.Errorf("%w: hex %d", ErrInvalidPacked, v)
		}
	}
	return 0, fmt.Errorf("%w: pack tag %d", ErrInvalidToken, tag)
}

func (d *Decoder) readJIDPair() (any, error) {
	user, err := d.readStringLike()
	if err != nil {
		return nil, err
	}
	server, err := d.readStringLike()
	if err != nil {
		return nil, err
	}
	s, ok := server.(string)
	if !ok || s == "" {
		return nil, fmt.Errorf("%w: JID pair without server", ErrInvalidNode)
	}
	u, _ := user.(string)
	return NewJID(u, s), nil
}

func (d *Decoder) readADJID() (any, error) {
	agent, err := d.readByte()
	if err != nil {
		return nil, err
	}
	device, err := d.readByte()
	if err != nil {
		return nil, err
	}
	user, err := d.readStringLike()
	if err != nil {
		return nil, err
	}
	u, _ := user.(string)
	return NewADJID(u, agent, device), nil
}

func (d *Decoder) readFBJID() (any, error) {
	user, err := d.readStringLike()
	if err != nil {
		return nil, err
	}
	device, err := d.readInt(2)
	if err != nil {
		return nil, err
	}
	server, err := d.readStringLike()
	if err != nil {
		return nil, err
	}
	return JID{User: toStringOrBytes(user), Device: uint16(device), Server: toStringOrBytes(server)}, nil
}

func (d *Decoder) readInteropJID() (any, error) {
	user, err := d.readStringLike()
	if err != nil {
		return nil, err
	}
	device, err := d.readInt(2)
	if err != nil {
		return nil, err
	}
	integrator, err := d.readInt(2)
	if err != nil {
		return nil, err
	}
	server, err := d.readStringLike()
	if err != nil {
		return nil, err
	}
	return JID{User: toStringOrBytes(user), Device: uint16(device), Integrator: uint16(integrator), Server: toStringOrBytes(server)}, nil
}

func toStringOrBytes(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// DecodeStream reads every node in the stream.
func DecodeStream(dict *token.Dictionary, stream []byte) ([]Node, error) {
	dec := NewDecoder(dict, stream)
	var nodes []Node
	for dec.index < len(dec.data) {
		n, err := dec.ReadNode()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// Unpack strips the stream flag byte and inflates zlib-compressed payloads.
func Unpack(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrTruncated
	}
	flag, body := data[0], data[1:]
	switch {
	case flag&streamFlagZlib != 0:
		r, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedData, err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("%w: inflate: %v", ErrUnsupportedData, err)
		}
		return out, nil
	case flag == streamFlagRaw:
		return body, nil
	default:
		return nil, fmt.Errorf("%w: unknown flag 0x%02x", ErrUnsupportedData, flag)
	}
}

// Decode unpacks the payload and returns the single top-level node.
func Decode(dict *token.Dictionary, payload []byte) (Node, error) {
	stream, err := Unpack(payload)
	if err != nil {
		return Node{}, err
	}
	dec := NewDecoder(dict, stream)
	n, err := dec.ReadNode()
	if err != nil {
		return Node{}, err
	}
	if dec.index != len(stream) {
		return Node{}, fmt.Errorf("%w: %d bytes left", ErrTrailingData, len(stream)-dec.index)
	}
	return n, nil
}

// DecodeDefault is Decode with the built-in dictionary.
func DecodeDefault(payload []byte) (Node, error) { return Decode(token.Default(), payload) }

// ParseJIDAttr is a helper to coerce values that decode to numbers.
func ParseJIDAttr(v any) (JID, bool) {
	switch t := v.(type) {
	case JID:
		return t, true
	case string:
		j, err := ParseJID(t)
		if err != nil {
			return JID{}, false
		}
		return j, true
	}
	return JID{}, false
}
