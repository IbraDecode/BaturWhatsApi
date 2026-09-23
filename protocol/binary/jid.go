package binary

import (
	"fmt"
	"strconv"
	"strings"
)

// Server constants for recognized WhatsApp servers.
const (
	ServerUser      = "s.whatsapp.net"
	ServerGroup     = "g.us"
	ServerBroadcast = "broadcast"
	ServerLID       = "lid"
	ServerNews      = "newsletter"
	ServerMSGram    = "msgr"
	ServerInterop   = "interop"
	ServerHosted    = "hosted"
	ServerHostedLID = "hosted.lid"
	ServerDevice    = "s.whatsapp.net"
)

// Agent/domain values carried in ADJID encodings.
const (
	AgentWhatsApp  uint8 = 0
	AgentLID       uint8 = 1
	AgentHosted    uint8 = 128
	AgentHostedLID uint8 = 129
)

// JID identifies an account, device or server endpoint.
type JID struct {
	User       string
	RawAgent   uint8
	Device     uint16
	Integrator uint16
	Server     string
}

// NewJID builds a plain user@server JID.
func NewJID(user, server string) JID { return JID{User: user, Server: server} }

// NewADJID interprets the (agent, device) pair of an ADJID wire encoding.
func NewADJID(user string, agent uint8, device uint8) JID {
	switch agent {
	case AgentLID:
		return JID{User: user, Device: uint16(device), Server: ServerLID}
	case AgentHosted:
		return JID{User: user, Device: uint16(device), Server: ServerHosted}
	case AgentHostedLID:
		return JID{User: user, Device: uint16(device), Server: ServerHostedLID}
	case AgentWhatsApp:
		return JID{User: user, Device: uint16(device), Server: ServerUser}
	default:
		// A non-domain agent byte means the wire device byte is the low
		// device byte and the high byte is folded in the agent position.
		return JID{User: user, RawAgent: agent, Device: uint16(device), Server: ServerUser}
	}
}

// ActualAgent returns the agent byte to use when serializing this JID as an
// ADJID (domain-first semantics, matching the ADJID wire format).
func (j JID) ActualAgent() uint8 {
	switch j.Server {
	case ServerUser:
		return AgentWhatsApp
	case ServerLID:
		return AgentLID
	case ServerHosted:
		return AgentHosted
	case ServerHostedLID:
		return AgentHostedLID
	default:
		return j.RawAgent
	}
}

// IsUserLike reports whether this JID can be encoded as an ADJID when it
// carries a device number.
func (j JID) isADJIDEncodable() bool {
	switch j.Server {
	case ServerUser, ServerLID, ServerHosted, ServerHostedLID:
		return j.Device > 0 || j.RawAgent != 0
	}
	return false
}

func (j JID) String() string {
	switch {
	case j.Server == "":
		return ""
	case j.RawAgent > 0:
		return fmt.Sprintf("%s.%d:%d@%s", j.User, j.RawAgent, j.Device, j.Server)
	case j.Device > 0 && (j.Server == ServerUser || j.Server == ServerLID):
		return fmt.Sprintf("%s:%d@%s", j.User, j.Device, j.Server)
	case j.User != "":
		return j.User + "@" + j.Server
	default:
		return j.Server
	}
}

// ParseJID parses the canonical string form of a JID.
func ParseJID(raw string) (JID, error) {
	user, server, ok := strings.Cut(raw, "@")
	if !ok {
		if raw == "" {
			return JID{}, fmt.Errorf("empty JID")
		}
		// Bare server JIDs.
		return JID{Server: raw}, nil
	}
	var integrator uint16
	if at := strings.LastIndex(user, "@"); at >= 0 {
		// Integrator JIDs look like u@i@server.
		iv, err := strconv.ParseUint(user[at+1:], 10, 16)
		if err != nil {
			return JID{}, fmt.Errorf("parse JID %q: bad integrator", raw)
		}
		integrator = uint16(iv)
		user = user[:at]
		server = ServerInterop
	}
	var agent uint8
	if dot := strings.IndexByte(user, '.'); dot >= 0 {
		av, err := strconv.ParseUint(user[dot+1:], 10, 8)
		if err != nil {
			return JID{}, fmt.Errorf("parse JID %q: bad agent", raw)
		}
		agent = uint8(av)
		user = user[:dot]
	}
	var device uint16
	if colon := strings.IndexByte(user, ':'); colon >= 0 {
		dv, err := strconv.ParseUint(user[colon+1:], 10, 16)
		if err != nil {
			return JID{}, fmt.Errorf("parse JID %q: bad device", raw)
		}
		device = uint16(dv)
		user = user[:colon]
	}
	return JID{User: user, RawAgent: agent, Device: device, Integrator: integrator, Server: server}, nil
}
