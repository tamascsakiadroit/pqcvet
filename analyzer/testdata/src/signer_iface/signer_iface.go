// Known limitation: when the static type is the crypto.Signer interface,
// method dispatch resolves to package "crypto", not the underlying concrete
// package, so no rule fires on the s.Sign call. This fixture documents
// current behavior — if either side flips (the keygen stops firing, or the
// interface call starts firing), the test breaks and the change is forced
// to be conscious.
package signer_iface

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func sign() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // want "MEDIUM.*ECDSA.*shor.*signature"
	var s crypto.Signer = priv
	_, _ = s.Sign(rand.Reader, []byte("digest......."), nil) // not flagged: static type is crypto.Signer
}
