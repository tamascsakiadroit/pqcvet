// Aliased import — resolution must go through go/types, not the source text.
package alias

import (
	"crypto/rand"
	r "crypto/rsa"
)

func keygen() {
	k, _ := r.GenerateKey(rand.Reader, 2048) // want "HIGH.*RSA.*shor.*encryption"
	_ = k
}
