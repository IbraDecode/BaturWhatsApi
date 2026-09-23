// session auth policies (ADR-0005).
package session

import (
	"crypto/ed25519"
	"time"

	"github.com/ibradecode/baturwhatsapi/security/wacert"
)

// TrustedRootAuth verifies the WhatsApp Noise certificate chain against a
// trust root. This is the production policy.
func TrustedRootAuth(root ed25519.PublicKey) ServerAuth {
	return func(staticPub, certBlob []byte) error {
		return wacert.Verify(certBlob, staticPub, root, time.Now())
	}
}

// PinFirstContact trusts the server static key seen at registration time
// and rejects every later key. Suitable for controlled environments and
// integration tests; TrustedRootAuth supersedes it for production.
func PinFirstContact(pin *[]byte) ServerAuth {
	return func(staticPub, _ []byte) error {
		if *pin == nil {
			cp := make([]byte, len(staticPub))
			copy(cp, staticPub)
			*pin = cp
			return nil
		}
		if len(staticPub) != len(*pin) {
			return ErrServerRejected
		}
		for i := range staticPub {
			if staticPub[i] != (*pin)[i] {
				return ErrServerRejected
			}
		}
		return nil
	}
}
