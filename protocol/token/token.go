// Package token provides the WhatsApp binary protocol dictionaries and tag
// constants used by the BaturWhatsApi protocol engine.
//
// The tables are protocol data (predefined string tokens shared by every
// WhatsApp Web implementation). They are loaded from generated data files at
// runtime so the engine can hot-swap dictionary revisions without rebuilds.
package token

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// Type tokens used in the binary node representation.
const (
	ListEmpty   = 0
	Dictionary0 = 236
	Dictionary1 = 237
	Dictionary2 = 238
	Dictionary3 = 239
	InteropJID  = 245
	FBJID       = 246
	ADJID       = 247
	List8       = 248
	List16      = 249
	JIDPair     = 250
	Hex8        = 251
	Binary8     = 252
	Binary20    = 253
	Binary32    = 254
	Nibble8     = 255
)

// Other limits.
const (
	PackedMax     = 127
	SingleByteMax = 256
)

//go:embed tokens_v3.json
var defaultTokensJSON []byte

// Dictionary is a resolved token dictionary usable by encoders and decoders.
type Dictionary struct {
	Version        int
	SingleByte     []string
	DoubleByte     [][]string
	singleIndex    map[string]byte
	doubleIndex    map[string][2]byte
}

type dictFile struct {
	Version    int        `json:"version"`
	SingleByte []string   `json:"single"`
	DoubleByte [][]string `json:"double"`
}

// Default returns the built-in dictionary revision shipped with the engine.
func Default() *Dictionary {
	d, err := FromJSON(defaultTokensJSON)
	if err != nil {
		panic("baturwhatsapi: embedded token table is invalid: " + err.Error())
	}
	return d
}

// FromJSON parses a dictionary from its JSON representation.
func FromJSON(data []byte) (*Dictionary, error) {
	var f dictFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse token dictionary: %w", err)
	}
	if len(f.SingleByte) > SingleByteMax {
		return nil, fmt.Errorf("too many single byte tokens: %d", len(f.SingleByte))
	}
	if len(f.DoubleByte) > 4 {
		return nil, fmt.Errorf("too many double byte dictionaries: %d", len(f.DoubleByte))
	}
	d := &Dictionary{
		Version:     f.Version,
		SingleByte:  f.SingleByte,
		DoubleByte:  f.DoubleByte,
		singleIndex: make(map[string]byte, len(f.SingleByte)),
		doubleIndex: make(map[string][2]byte, 256*4),
	}
	for i, t := range d.SingleByte {
		if t != "" {
			d.singleIndex[t] = byte(i)
		}
	}
	for di, list := range d.DoubleByte {
		for i, t := range list {
			if _, dup := d.doubleIndex[t]; !dup {
				d.doubleIndex[t] = [2]byte{byte(di), byte(i)}
			}
		}
	}
	return d, nil
}

// MustParseJSON is FromJSON but panics on error; intended for tests and
// static data initialization.
func MustParseJSON(data string) *Dictionary {
	d, err := FromJSON([]byte(data))
	if err != nil {
		panic(err)
	}
	return d
}

// SingleToken returns the string for a single-byte token index.
func (d *Dictionary) SingleToken(index int) (string, bool) {
	if index < 1 || index >= len(d.SingleByte) || d.SingleByte[index] == "" {
		return "", false
	}
	return d.SingleByte[index], true
}

// DoubleToken returns the string for a (dictionary, index) pair.
func (d *Dictionary) DoubleToken(dict, index int) (string, bool) {
	if dict < 0 || dict >= len(d.DoubleByte) || index < 0 || index >= len(d.DoubleByte[dict]) {
		return "", false
	}
	return d.DoubleByte[dict][index], true
}

// IndexOfSingle returns the single-byte token index for a string.
func (d *Dictionary) IndexOfSingle(t string) (byte, bool) {
	i, ok := d.singleIndex[t]
	return i, ok
}

// IndexOfDouble returns (dictionary, index) for a double-byte token string.
func (d *Dictionary) IndexOfDouble(t string) (byte, byte, bool) {
	v, ok := d.doubleIndex[t]
	if !ok {
		return 0, 0, false
	}
	return v[0], v[1], true
}

// Lookup resolves an arbitrary literal: dictionary tokens return their index
// encoding info, everything else reports not found.
func (d *Dictionary) Lookup(t string) (kind string, a, b byte) {
	if i, ok := d.singleIndex[t]; ok {
		return "single", i, 0
	}
	if v, ok := d.doubleIndex[t]; ok {
		return "double", v[0], v[1]
	}
	return "", 0, 0
}

func (d *Dictionary) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "token.Dictionary{v%d single=%d", d.Version, len(d.SingleByte))
	for _, l := range d.DoubleByte {
		fmt.Fprintf(&sb, " double+%d", len(l))
	}
	sb.WriteByte('}')
	return sb.String()
}
