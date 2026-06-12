// Method-dispatch on a concrete *ecdsa.PrivateKey resolves through go/types
// to crypto/ecdsa.Sign, so the rule fires — the analyzer is not limited to
// package-qualified call sites. This fixture locks that property in.
package signer_method

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func sign() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)  // want "MEDIUM.*ECDSA.*shor.*signature"
	_, _ = priv.Sign(rand.Reader, []byte("digest......."), nil) // want "MEDIUM.*ECDSA.*shor.*signature"
}
