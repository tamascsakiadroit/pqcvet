// crypto/dsa is matched by a catch-all (Symbols: nil) rule. Any reference
// — including a type-only mention — must fire, since the whole package is
// Shor-broken and already deprecated in the standard library.
package dsa_basic

import "crypto/dsa"

var _ dsa.PrivateKey // want "MEDIUM.*DSA.*shor.*signature"
