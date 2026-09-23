// Package wapb defines WhatsApp-web protocol buffer message shapes used by
// the handshake and control payloads, built on the engine's own minimal pb
// codec (no code generation, no protobuf runtime dependency).
package wapb

import "github.com/ibradecode/baturwhatsapi/protocol/pb"

// HandshakeMessage field numbers (per WhatsApp web protocol).
const (
	HSFieldClientHello  = 1
	HSFieldServerHello  = 2
	HSFieldClientFinish = 3
	HSFieldSubConnHello = 4
)

// Hello sub-message field numbers.
const (
	HFLEphemeral = 1
	HFLStatic    = 2
	HFLPayload   = 3
)

// ClientHello is { ephemeral: bytes = 1; payload: bytes = 3 }.
type ClientHello struct {
	Ephemeral []byte
	Payload   []byte
}

func (c *ClientHello) Build() []byte {
	b := pb.NewBuilder().Bytes(HFLEphemeral, c.Ephemeral)
	if len(c.Payload) > 0 {
		b = b.Bytes(HFLPayload, c.Payload)
	}
	return b.Build()
}

func ParseClientHello(m pb.Message) (*ClientHello, error) {
	v := &ClientHello{}
	if e, ok := m.GetBytes(HFLEphemeral); ok {
		v.Ephemeral = e
	}
	if p, ok := m.GetBytes(HFLPayload); ok {
		v.Payload = p
	}
	return v, nil
}

// ServerHello is { ephemeral = 1; static = 2; payload = 3 }.
type ServerHello struct {
	Ephemeral []byte
	Static    []byte
	Payload   []byte
}

func (c *ServerHello) Build() []byte {
	b := pb.NewBuilder().Bytes(HFLEphemeral, c.Ephemeral)
	if len(c.Static) > 0 {
		b = b.Bytes(HFLStatic, c.Static)
	}
	if len(c.Payload) > 0 {
		b = b.Bytes(HFLPayload, c.Payload)
	}
	return b.Build()
}

func ParseServerHello(m pb.Message) (*ServerHello, error) {
	v := &ServerHello{}
	if e, ok := m.GetBytes(HFLEphemeral); ok {
		v.Ephemeral = e
	}
	if s, ok := m.GetBytes(HFLStatic); ok {
		v.Static = s
	}
	if p, ok := m.GetBytes(HFLPayload); ok {
		v.Payload = p
	}
	return v, nil
}

// ClientFinish is { static = 1; payload = 2 }.
type ClientFinish struct {
	Static  []byte
	Payload []byte
}

func (c *ClientFinish) Build() []byte {
	return pb.NewBuilder().
		Bytes(HFLEphemeral, c.Static).
		Bytes(HFLPayload, c.Payload).Build()
}

func ParseClientFinish(m pb.Message) (*ClientFinish, error) {
	v := &ClientFinish{}
	if s, ok := m.GetBytes(HFLEphemeral); ok {
		v.Static = s
	}
	if p, ok := m.GetBytes(HFLPayload); ok {
		v.Payload = p
	}
	return v, nil
}

// WrapTop wraps a sub-message into a HandshakeMessage envelope field.
func WrapTop(fieldNum uint32, inner []byte) []byte {
	return pb.NewBuilder().Bytes(fieldNum, inner).Build()
}

// UnwrapTop returns the nested message of the given top field, or nil.
func UnwrapTop(data []byte, fieldNum uint32) (pb.Message, error) {
	msg, err := pb.Parse(data)
	if err != nil {
		return nil, err
	}
	inner, ok := msg.GetBytes(fieldNum)
	if !ok {
		return nil, nil
	}
	return pb.Parse(inner)
}
