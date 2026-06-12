// Negative fixture: crypto/mlkem is a PQC KEM and must NOT be flagged.
package mlkem_safe

import "crypto/mlkem"

func kex() {
	k, _ := mlkem.GenerateKey768()
	_ = k
}
