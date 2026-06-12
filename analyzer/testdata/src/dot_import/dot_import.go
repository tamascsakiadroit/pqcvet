// Dot-imported packages turn what would be a SelectorExpr into a bare
// *ast.Ident — the analyzer walks idents, so the rule still fires.
package dot_import

import (
	"crypto/rand"
	. "crypto/rsa"
)

func keygen() {
	k, _ := GenerateKey(rand.Reader, 2048) // want "HIGH.*RSA.*shor.*encryption"
	_ = k
}
