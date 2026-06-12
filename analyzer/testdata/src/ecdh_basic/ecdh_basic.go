// crypto/ecdh — Shor-broken key exchange. Curve constructors are NOT
// flagged on their own (would double-flag with GenerateKey); GenerateKey,
// NewPrivateKey/NewPublicKey (key import), and the ECDH method (the actual
// HNDL-relevant shared-secret op) are all caught.
package ecdh_basic

import (
	"crypto/ecdh"
	"crypto/rand"
)

func chained() {
	_, _ = ecdh.X25519().GenerateKey(rand.Reader) // want "HIGH.*ECDH.*shor.*keyexchange"
}

func stored() {
	curve := ecdh.P256()
	_, _ = curve.GenerateKey(rand.Reader) // want "HIGH.*ECDH.*shor.*keyexchange"
}

func parsedAndExchange(rawPriv, rawPeer []byte) {
	curve := ecdh.X25519()
	priv, _ := curve.NewPrivateKey(rawPriv) // want "HIGH.*ECDH.*shor.*keyexchange"
	peer, _ := curve.NewPublicKey(rawPeer)  // want "HIGH.*ECDH.*shor.*keyexchange"
	_, _ = priv.ECDH(peer)                  // want "HIGH.*ECDH.*shor.*keyexchange"
}
