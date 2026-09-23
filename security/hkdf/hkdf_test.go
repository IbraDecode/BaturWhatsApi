package hkdf

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRFC5869SHA256 uses the official SHA-256 test vectors from RFC 5869
// Appendix A (A.1, A.2, A.3), fetched and transcribed verbatim from
// https://www.rfc-editor.org/rfc/rfc5869.txt
func TestRFC5869SHA256(t *testing.T) {
	cases := []struct {
		name            string
		ikm, salt, info string
		l               int
		prk, okm        string
	}{
		{
			name: "A.1 basic",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "000102030405060708090a0b0c",
			info: "f0f1f2f3f4f5f6f7f8f9",
			l:    42,
			prk:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			okm:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "A.2 longer",
			ikm:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			l:    82,
			prk:  "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			okm:  "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name: "A.3 zero salt/info",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "",
			info: "",
			l:    42,
			prk:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			okm:  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ikm := mustHex(t, tc.ikm)
			var salt []byte
			if tc.salt != "" {
				salt = mustHex(t, tc.salt)
			}
			prk := Extract(ikm, salt)
			if want := mustHex(t, tc.prk); !bytes.Equal(prk, want) {
				t.Fatalf("PRK mismatch\ngot  %x\nwant %x", prk, want)
			}
			okm, err := Expand(prk, mustHex(t, tc.info), tc.l)
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, tc.okm); !bytes.Equal(okm, want) {
				t.Fatalf("OKM mismatch\ngot  %x\nwant %x", okm, want)
			}
			// One-shot Derive must match.
			got, err := Derive(ikm, salt, mustHex(t, tc.info), tc.l)
			if err != nil || !bytes.Equal(got, mustHex(t, tc.okm)) {
				t.Fatalf("Derive mismatch: %v", err)
			}
		})
	}
}

func TestKeysSplit(t *testing.T) {
	a, b, err := Keys([]byte("shared"), []byte("salt"), nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("key halves must differ")
	}
	full, _ := Derive([]byte("shared"), []byte("salt"), nil, 64)
	if !bytes.Equal(append(a, b...), full) {
		t.Fatal("Keys must split one contiguous derivation")
	}
}
