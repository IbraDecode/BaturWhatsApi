// Package binary implements BaturWhatsApi's protocol node codec: WhatsApp
// Web's binary XML ("WAWebMulti") node serialization used on the control
// socket.
//
// This is the engine's own implementation: Node values are decoded into a
// normalized tree (see Node) that the protocol layer hands to the domain
// layer. Raw protocol objects must never cross into the public API.
package binary

import (
	"encoding/json"
	"fmt"
)

// Attrs holds node attributes. Values are one of: string, int64, float64,
// bool, []byte, or JID after decoding.
type Attrs map[string]any

// Node is a protocol node (XML element analog) in WhatsApp's binary encoding.
// Content is nil, string, []byte, JID, or []Node.
type Node struct {
	Tag     string
	Attrs   Attrs
	Content any
}

// NewNode builds a node with children.
func NewNode(tag string, attrs Attrs, content ...Node) Node {
	n := Node{Tag: tag, Attrs: attrs}
	if len(content) > 0 {
		n.Content = content
	}
	return n
}

// NewTextNode builds a node with a text content.
func NewTextNode(tag, text string) Node {
	return Node{Tag: tag, Content: text}
}

// NewBinaryNode builds a node with binary content.
func NewBinaryNode(tag string, data []byte) Node {
	return Node{Tag: tag, Content: data}
}

// Children returns the content as a node list, or nil.
func (n Node) Children() []Node {
	if c, ok := n.Content.([]Node); ok {
		return c
	}
	return nil
}

// ChildByTag returns the first direct child with the given tag.
func (n Node) ChildByTag(tag string) (Node, bool) {
	for _, c := range n.Children() {
		if c.Tag == tag {
			return c, true
		}
	}
	return Node{}, false
}

// ChildrenByTag returns all direct children with the given tag.
func (n Node) ChildrenByTag(tag string) []Node {
	var out []Node
	for _, c := range n.Children() {
		if c.Tag == tag {
			out = append(out, c)
		}
	}
	return out
}

// DeepChild walks nested tags, returning the first match at each level.
func (n Node) DeepChild(tags ...string) (Node, bool) {
	cur := n
	for _, tag := range tags {
		next, ok := cur.ChildByTag(tag)
		if !ok {
			return Node{}, false
		}
		cur = next
	}
	return cur, true
}

// BytesContent returns node content as bytes for protobuf-style payloads.
// Because the wire format stores text and binary identically, a valid-UTF-8
// binary payload may decode as string; this helper normalizes both forms.
func (n Node) BytesContent() ([]byte, bool) {
	switch c := n.Content.(type) {
	case []byte:
		return c, true
	case string:
		return []byte(c), true
	}
	return nil, false
}

// TextContent returns node content as a string when present.
func (n Node) TextContent() (string, bool) {
	switch c := n.Content.(type) {
	case string:
		return c, true
	case []byte:
		return string(c), true
	}
	return "", false
}

// StringAttr returns an attribute as a string. Numeric values are formatted
// canonically.
func (n Node) StringAttr(key string) (string, bool) {
	v, ok := n.Attrs[key]
	if !ok || v == nil {
		return "", false
	}
	switch typed := v.(type) {
	case string:
		return typed, true
	case []byte:
		return string(typed), true
	case JID:
		return typed.String(), true
	case int64:
		return fmt.Sprintf("%d", typed), true
	case float64:
		return fmt.Sprintf("%v", typed), true
	case bool:
		if typed {
			return "true", true
		}
		return "false", true
	default:
		return fmt.Sprintf("%v", typed), true
	}
}

// MustStringAttr is StringAttr ignoring the presence flag.
func (n Node) MustStringAttr(key string) string {
	s, _ := n.StringAttr(key)
	return s
}

// JIDAttr returns an attribute as a JID (parsing string attributes if needed).
func (n Node) JIDAttr(key string) (JID, bool) {
	v, ok := n.Attrs[key]
	if !ok {
		return JID{}, false
	}
	switch typed := v.(type) {
	case JID:
		return typed, true
	case string:
		jid, err := ParseJID(typed)
		if err != nil {
			return JID{}, false
		}
		return jid, true
	}
	return JID{}, false
}

// nodeJSON is the observability/debug representation of a node.
type nodeJSON struct {
	Tag     string          `json:"tag"`
	Attrs   map[string]any  `json:"attrs,omitempty"`
	Content json.RawMessage `json:"content,omitempty"`
}

// MarshalJSON renders nodes for logs and the debug API (not the wire format).
func (n Node) MarshalJSON() ([]byte, error) {
	out := nodeJSON{Tag: n.Tag}
	if len(n.Attrs) > 0 {
		out.Attrs = make(map[string]any, len(n.Attrs))
		for k, v := range n.Attrs {
			switch typed := v.(type) {
			case []byte:
				out.Attrs[k] = typed
			default:
				out.Attrs[k] = typed
			}
		}
	}
	switch c := n.Content.(type) {
	case nil:
	case string:
		b, _ := json.Marshal(c)
		out.Content = b
	case []byte:
		b, _ := json.Marshal(c)
		out.Content = b
	case []Node:
		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		out.Content = b
	default:
		b, _ := json.Marshal(fmt.Sprintf("%v", c))
		out.Content = b
	}
	return json.Marshal(out)
}

func (n *Node) UnmarshalJSON(data []byte) error {
	var raw nodeJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	n.Tag = raw.Tag
	n.Attrs = Attrs{}
	for k, v := range raw.Attrs {
		n.Attrs[k] = v
	}
	if len(raw.Content) == 0 {
		return nil
	}
	switch raw.Content[0] {
	case '[':
		var kids []Node
		if err := json.Unmarshal(raw.Content, &kids); err != nil {
			return err
		}
		n.Content = kids
	case '"':
		var s string
		if err := json.Unmarshal(raw.Content, &s); err != nil {
			return err
		}
		n.Content = s
	default:
		return fmt.Errorf("binary: unsupported node content JSON")
	}
	return nil
}
