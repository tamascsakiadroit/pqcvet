package ecdsa_basic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func keygen() {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // want "MEDIUM.*ECDSA.*shor.*signature"
	_ = k
}

func sign(priv *ecdsa.PrivateKey, digest []byte) {
	_, _ = ecdsa.SignASN1(rand.Reader, priv, digest) // want "MEDIUM.*ECDSA.*shor.*signature"
}
