package ed25519_basic

import (
	"crypto/ed25519"
	"crypto/rand"
)

func sign() {
	_, priv, _ := ed25519.GenerateKey(rand.Reader) // want "MEDIUM.*Ed25519.*shor.*signature"
	_ = ed25519.Sign(priv, []byte("hi"))           // want "MEDIUM.*Ed25519.*shor.*signature"
}
