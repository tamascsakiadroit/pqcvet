// Realistic HNDL path: keys are loaded from disk/KMS/x509, not generated
// in-process. The pqcvet rule must fire on the *PrivateKey.Sign and
// *PrivateKey.Decrypt method calls — these resolve to crypto/rsa via
// go/types, and the package-level Sign*/Decrypt* rules wouldn't cover them.
package rsa_parsed

import (
	"crypto/rand"
	"crypto/rsa"
)

func signAndDecrypt(priv *rsa.PrivateKey, digest, ciphertext []byte) {
	_, _ = priv.Sign(rand.Reader, digest, nil)                       // want "MEDIUM.*RSA.*shor.*signature"
	_, _ = priv.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{}) // want "HIGH.*RSA.*shor.*encryption"
}
