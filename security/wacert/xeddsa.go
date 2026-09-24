package wacert

import (
	"crypto/ed25519"
	"math/big"
)

// p = 2^255 - 19, the Curve25519 field prime.
var fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// verifyXEdDSA checks a Curve25519 XEdDSA signature.
//
// The Montgomery u-coordinate converts to an Edwards y-coordinate with
// y = (u-1)/(u+1). The signature's top bit carries the Edwards sign and is
// cleared before ed25519.Verify.
func verifyXEdDSA(mont, msg, sig []byte) bool {
	if len(mont) != 32 || len(sig) != 64 {
		return false
	}
	u := le(mont)
	u.SetBit(u, 255, 0)
	one := big.NewInt(1)
	num := new(big.Int).Sub(u, one)
	den := new(big.Int).Add(u, one)
	den.ModInverse(den, fieldPrime)
	y := new(big.Int).Mul(num, den)
	y.Mod(y, fieldPrime)
	ed := leBytes(y)
	sig = append([]byte(nil), sig...)
	ed[31] |= sig[63] & 0x80
	sig[63] &= 0x7f
	return ed25519.Verify(ed, msg, sig)
}

func le(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(rev)
}

func leBytes(n *big.Int) []byte {
	be := n.Bytes()
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[len(be)-1-i]
	}
	return out
}
