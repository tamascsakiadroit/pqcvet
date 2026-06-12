// crypto.Hash registry constants resolve to package "crypto", not the
// dedicated algorithm package — `crypto.SHA1.New()` and the like must
// still surface so signing/HMAC config sites don't silently slip past.
package crypto_hash

import "crypto"

func registry() {
	_ = crypto.MD5.New()     // want "MEDIUM.*MD5.*classical.*hashing"
	_ = crypto.SHA1.New()    // want "MEDIUM.*SHA-1.*classical.*hashing"
	_ = crypto.MD5SHA1.New() // want "MEDIUM.*MD5\\+SHA-1.*classical.*hashing"
}
