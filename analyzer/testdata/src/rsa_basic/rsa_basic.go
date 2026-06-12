package rsa_basic

import (
	"crypto/rand"
	"crypto/rsa"
)

func keygen() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048) // want "HIGH.*RSA.*shor.*encryption"
	_ = k
}

func sign(priv *rsa.PrivateKey, msg []byte) {
	_, _ = rsa.SignPKCS1v15(rand.Reader, priv, 0, msg) // want "MEDIUM.*RSA.*shor.*signature"
}

func enc(pub *rsa.PublicKey, msg []byte) {
	_, _ = rsa.EncryptOAEP(nil, rand.Reader, pub, msg, nil) // want "HIGH.*RSA.*shor.*encryption"
}
