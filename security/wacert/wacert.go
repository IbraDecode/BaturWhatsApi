// Package wacert verifies WhatsApp web's Noise certificate chains: a trust
// root signs the intermediate certificate, the intermediate signs the leaf,
// and the leaf binds the server's noise static key.
//
// Verification is pure stdlib (crypto/ed25519) over the engine's own pb
// codec. The wire schema is protocol data:
//
//	CertChain{ leaf=1, intermediate=2 }
//	NoiseCertificate{ details(bytes)=1, signature(bytes)=2 }
//	Details{ serial=1, issuerSerial=2, key=3, notBefore=4, notAfter=5 }
package wacert

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/ibradecode/baturwhatsapi/protocol/pb"
)

// Trust roots (protocol facts).
var (
	// RootPubKey is WhatsApp's long-lived certificate root public key.
	RootPubKey = ed25519.PublicKey{
		0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71,
		0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
		0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c,
		0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
	}
	// RootSerial is the expected issuer serial for the intermediate.
	RootSerial uint32 = 0
)

// Errors.
var (
	ErrMalformed   = errors.New("wacert: malformed chain")
	ErrBadSig      = errors.New("wacert: signature verification failed")
	ErrExpired     = errors.New("wacert: certificate expired or not yet valid")
	ErrKeyMismatch = errors.New("wacert: leaf key does not match server static")
)

type cert struct {
	Details   []byte
	Signature []byte
}

type details struct {
	Serial       uint32
	IssuerSerial uint32
	Key          []byte
	NotBefore    uint64
	NotAfter     uint64
}

func parseCert(b []byte) (*cert, error) {
	m, err := pb.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	c := &cert{}
	c.Details, _ = m.GetBytes(1)
	c.Signature, _ = m.GetBytes(2)
	if len(c.Details) == 0 || len(c.Signature) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	return c, nil
}

func parseDetails(raw []byte) (*details, error) {
	m, err := pb.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: details: %v", ErrMalformed, err)
	}
	d := &details{}
	if v, ok := m.GetUint(1); ok {
		d.Serial = uint32(v)
	}
	if v, ok := m.GetUint(2); ok {
		d.IssuerSerial = uint32(v)
	}
	d.Key, _ = m.GetBytes(3)
	if v, ok := m.GetUint(4); ok {
		d.NotBefore = v
	}
	if v, ok := m.GetUint(5); ok {
		d.NotAfter = v
	}
	if len(d.Key) != 32 {
		return nil, fmt.Errorf("%w: key length %d", ErrMalformed, len(d.Key))
	}
	return d, nil
}

func checkValidity(d *details, now time.Time) error {
	nb := time.Unix(int64(d.NotBefore), 0)
	na := time.Unix(int64(d.NotAfter), 0)
	if now.Before(nb) {
		return fmt.Errorf("%w: not valid before %s", ErrExpired, nb.UTC())
	}
	if now.After(na) {
		return fmt.Errorf("%w: expired at %s", ErrExpired, na.UTC())
	}
	return nil
}

// Verify checks chainOfTrust(certChain, serverStatic) at time now:
//   - intermediate signed by rootPubKey, issuerSerial == rootSerial
//   - leaf signed by intermediate key, issuerSerial == intermediate serial
//   - leaf key == serverStatic, both certificates valid at now
//
// Pass wacert.RootPubKey for production use.
func Verify(certChain []byte, serverStatic []byte, rootPubKey ed25519.PublicKey, now time.Time) error {
	msg, err := pb.Parse(certChain)
	if err != nil {
		return fmt.Errorf("%w: chain: %v", ErrMalformed, err)
	}
	interRaw, ok := msg.GetBytes(2)
	if !ok {
		return ErrMalformed
	}
	leafRaw, ok := msg.GetBytes(1)
	if !ok {
		return ErrMalformed
	}
	inter, err := parseCert(interRaw)
	if err != nil {
		return fmt.Errorf("intermediate: %w", err)
	}
	leaf, err := parseCert(leafRaw)
	if err != nil {
		return fmt.Errorf("leaf: %w", err)
	}
	if len(rootPubKey) != ed25519.PublicKeySize {
		return errors.New("wacert: bad trust anchor length")
	}
	if !ed25519.Verify(rootPubKey, inter.Details, inter.Signature) {
		return fmt.Errorf("%w: intermediate", ErrBadSig)
	}
	interD, err := parseDetails(inter.Details)
	if err != nil {
		return fmt.Errorf("intermediate: %w", err)
	}
	if interD.IssuerSerial != RootSerial {
		return fmt.Errorf("wacert: unexpected intermediate issuer serial %d", interD.IssuerSerial)
	}
	if err := checkValidity(interD, now); err != nil {
		return fmt.Errorf("intermediate: %w", err)
	}
	interKey := ed25519.PublicKey(interD.Key)
	if !ed25519.Verify(interKey, leaf.Details, leaf.Signature) {
		return fmt.Errorf("%w: leaf", ErrBadSig)
	}
	leafD, err := parseDetails(leaf.Details)
	if err != nil {
		return fmt.Errorf("leaf: %w", err)
	}
	if leafD.IssuerSerial != interD.Serial {
		return fmt.Errorf("wacert: leaf issuer serial %d != intermediate serial %d",
			leafD.IssuerSerial, interD.Serial)
	}
	if err := checkValidity(leafD, now); err != nil {
		return fmt.Errorf("leaf: %w", err)
	}
	if !bytes.Equal(leafD.Key, serverStatic) {
		return ErrKeyMismatch
	}
	return nil
}

// BuildChain assembles a CertChain wire message (used by test/mock servers).
func BuildChain(leafDetails, leafSig, interDetails, interSig []byte) []byte {
	leaf := pb.NewBuilder().Bytes(1, leafDetails).Bytes(2, leafSig).Build()
	inter := pb.NewBuilder().Bytes(1, interDetails).Bytes(2, interSig).Build()
	return pb.NewBuilder().Bytes(1, leaf).Bytes(2, inter).Build()
}

// BuildDetails serializes certificate details (test/mock helper).
func BuildDetails(serial, issuerSerial uint32, key []byte, notBefore, notAfter time.Time) []byte {
	return pb.NewBuilder().
		Uint(1, uint64(serial)).
		Uint(2, uint64(issuerSerial)).
		Bytes(3, key).
		Uint(4, uint64(notBefore.Unix())).
		Uint(5, uint64(notAfter.Unix())).
		Build()
}
