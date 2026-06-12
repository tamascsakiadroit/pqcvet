// End-to-end exercise of the classical-weakness branch: identity-weak
// algorithms must flow through Exposure=classical and surface at the
// override severity (MEDIUM).
package grover_weak

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
)

func hashes(msg []byte) {
	_ = md5.New()     // want "MEDIUM.*MD5.*classical.*hashing"
	_ = md5.Sum(msg)  // want "MEDIUM.*MD5.*classical.*hashing"
	_ = sha1.New()    // want "MEDIUM.*SHA-1.*classical.*hashing"
	_ = sha1.Sum(msg) // want "MEDIUM.*SHA-1.*classical.*hashing"
}

func ciphers(key []byte) {
	_, _ = des.NewCipher(key)          // want "MEDIUM.*DES.*classical.*symmetric"
	_, _ = des.NewTripleDESCipher(key) // want "MEDIUM.*DES.*classical.*symmetric"
	_, _ = rc4.NewCipher(key)          // want "MEDIUM.*RC4.*classical.*symmetric"
}
