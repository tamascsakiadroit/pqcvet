package analyzer

import "github.com/tamascsakiadroit/pqcvet/finding"

// rules is the v1 detection table. Adding a package is one entry, not new code.
// Keep entries grouped by package and ordered from most-specific to least.
var rules = []Rule{
	// --- crypto/rsa ----------------------------------------------------------
	// RSA keys can be used for both encryption and signing, so GenerateKey is
	// classified as encryption (HIGH) to capture the HNDL worst case. ECDSA
	// and Ed25519 keys are signature-only by construction, hence MEDIUM there.
	{
		Pkg:         "crypto/rsa",
		Symbols:     []string{"GenerateKey", "GenerateMultiPrimeKey"},
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeEncryption,
		Algorithm:   "RSA",
		OID:         "1.2.840.113549.1.1.1",
		Remediation: "use ML-KEM (FIPS 203) for key exchange or ML-DSA (FIPS 204) for signatures",
	},
	{
		// "Sign" catches the *PrivateKey.Sign method on parsed keys — the
		// crypto.Signer-shaped path used after x509.ParsePKCS1PrivateKey,
		// which the package-level signers (SignPKCS1v15/SignPSS) don't cover.
		// crypto/rsa exports no other "Sign" symbol, so there's no collision.
		Pkg:         "crypto/rsa",
		Symbols:     []string{"Sign", "SignPKCS1v15", "SignPSS", "VerifyPKCS1v15", "VerifyPSS"},
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeSignature,
		Algorithm:   "RSA",
		OID:         "1.2.840.113549.1.1.1",
		Remediation: "use ML-DSA (FIPS 204) or a hybrid RSA+ML-DSA scheme",
	},
	{
		// "Decrypt" catches the *PrivateKey.Decrypt method (crypto.Decrypter)
		// on parsed keys — the realistic HNDL path when a key is loaded from
		// KMS/PEM/x509 and then used directly. crypto/rsa has no package-level
		// Decrypt symbol, so no collision with the explicit Decrypt* entries.
		Pkg:         "crypto/rsa",
		Symbols:     []string{"Decrypt", "EncryptOAEP", "DecryptOAEP", "EncryptPKCS1v15", "DecryptPKCS1v15", "DecryptPKCS1v15SessionKey"},
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeEncryption,
		Algorithm:   "RSA",
		OID:         "1.2.840.113549.1.1.1",
		Remediation: "use ML-KEM (FIPS 203) and a symmetric cipher",
	},

	// --- crypto/ecdsa --------------------------------------------------------
	{
		Pkg:         "crypto/ecdsa",
		Symbols:     []string{"GenerateKey", "Sign", "SignASN1", "Verify", "VerifyASN1"},
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeSignature,
		Algorithm:   "ECDSA",
		OID:         "1.2.840.10045.2.1",
		Remediation: "use ML-DSA (FIPS 204) or hybrid ECDSA+ML-DSA",
	},

	// --- crypto/ed25519 ------------------------------------------------------
	{
		Pkg:         "crypto/ed25519",
		Symbols:     []string{"GenerateKey", "Sign", "Verify", "VerifyWithOptions", "NewKeyFromSeed"},
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeSignature,
		Algorithm:   "Ed25519",
		OID:         "1.3.101.112",
		Remediation: "use ML-DSA (FIPS 204) or hybrid Ed25519+ML-DSA",
	},

	// --- crypto/ecdh ---------------------------------------------------------
	// Curve constructors (X25519, P256, ...) are intentionally skipped — they
	// almost always chain into GenerateKey, and double-flagging the same line
	// is noise. NewPrivateKey / NewPublicKey cover key-material import (PEM,
	// KMS, x509); ECDH() covers the actual shared-secret computation, which
	// is the HNDL-relevant operation when a long-term key is *parsed* rather
	// than generated in-process. All these dispatch through go/types to
	// crypto/ecdh, so stored-curve and chained forms both fire.
	{
		Pkg:         "crypto/ecdh",
		Symbols:     []string{"GenerateKey", "NewPrivateKey", "NewPublicKey", "ECDH"},
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeKeyExchange,
		Algorithm:   "ECDH",
		OID:         "1.3.132.1.12",
		Remediation: "use ML-KEM (FIPS 203) or hybrid X25519+ML-KEM-768",
	},

	// --- crypto/dsa ----------------------------------------------------------
	// Catch-all: the whole DSA package is Shor-broken and already deprecated
	// in the standard library. Any reference is worth flagging.
	{
		Pkg:         "crypto/dsa",
		Symbols:     nil,
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeSignature,
		Algorithm:   "DSA",
		OID:         "1.2.840.10040.4.1",
		Remediation: "DSA is deprecated and Shor-broken; use ML-DSA (FIPS 204)",
	},

	// --- identity-weak (classically broken) ---------------------------------
	// These algorithms are already broken by classical attacks (collisions
	// for MD5/SHA-1, brute force for single-DES, biases for RC4) — quantum
	// computers don't enter into it. Exposure=classical signals that to
	// downstream consumers (CBOM, dashboards), and Severity=MEDIUM is the
	// override that drives the diagnostic since the matrix has no classical
	// cells.
	{
		Pkg:         "crypto/md5",
		Symbols:     []string{"New", "Sum"},
		Exposure:    finding.ExposureClassical,
		Purpose:     finding.PurposeHashing,
		Severity:    finding.SeverityMedium,
		Algorithm:   "MD5",
		OID:         "1.2.840.113549.2.5",
		Remediation: "MD5 is collision-broken; use SHA-256 or SHA-3",
	},
	{
		Pkg:         "crypto/sha1",
		Symbols:     []string{"New", "Sum"},
		Exposure:    finding.ExposureClassical,
		Purpose:     finding.PurposeHashing,
		Severity:    finding.SeverityMedium,
		Algorithm:   "SHA-1",
		OID:         "1.3.14.3.2.26",
		Remediation: "SHA-1 is collision-broken; use SHA-256 or SHA-3",
	},
	// crypto.Hash registry constants. signing configs and HMAC setup commonly
	// pass crypto.MD5/SHA1 instead of importing the algorithm package directly,
	// and `crypto.SHA1.New()` resolves to package "crypto" not "crypto/sha1" —
	// so the dedicated rules above don't see it. Match the constants only;
	// matching "New" here would over-fire on any crypto.Hash.New call.
	{
		Pkg:         "crypto",
		Symbols:     []string{"MD5"},
		Exposure:    finding.ExposureClassical,
		Purpose:     finding.PurposeHashing,
		Severity:    finding.SeverityMedium,
		Algorithm:   "MD5",
		OID:         "1.2.840.113549.2.5",
		Remediation: "MD5 is collision-broken; use SHA-256 or SHA-3",
	},
	{
		Pkg:         "crypto",
		Symbols:     []string{"SHA1"},
		Exposure:    finding.ExposureClassical,
		Purpose:     finding.PurposeHashing,
		Severity:    finding.SeverityMedium,
		Algorithm:   "SHA-1",
		OID:         "1.3.14.3.2.26",
		Remediation: "SHA-1 is collision-broken; use SHA-256 or SHA-3",
	},
	{
		Pkg:         "crypto",
		Symbols:     []string{"MD5SHA1"},
		Exposure:    finding.ExposureClassical,
		Purpose:     finding.PurposeHashing,
		Severity:    finding.SeverityMedium,
		Algorithm:   "MD5+SHA-1",
		Remediation: "MD5+SHA-1 (legacy TLS 1.0/1.1 PRF) inherits MD5 weaknesses; use SHA-256 or SHA-3",
	},
	{
		// No OID: crypto/des.NewCipher and NewTripleDESCipher produce a
		// cipher.Block — the mode (CBC, ECB, CFB) is chosen by the caller,
		// and OIDs are mode-specific (desCBC=1.3.14.3.2.7,
		// des-EDE3-CBC=1.2.840.113549.3.7). A future mode-aware pass could
		// populate this; static symbol matching here cannot.
		Pkg:         "crypto/des",
		Symbols:     []string{"NewCipher", "NewTripleDESCipher"},
		Exposure:    finding.ExposureClassical,
		Purpose:     finding.PurposeSymmetric,
		Severity:    finding.SeverityMedium,
		Algorithm:   "DES",
		Remediation: "DES/3DES are brute-forceable; use AES-256",
	},
	{
		Pkg:         "crypto/rc4",
		Symbols:     []string{"NewCipher"},
		Exposure:    finding.ExposureClassical,
		Purpose:     finding.PurposeSymmetric,
		Severity:    finding.SeverityMedium,
		Algorithm:   "RC4",
		Remediation: "RC4 has known biases; use AES-256",
	},

	// --- safe (post-quantum) -------------------------------------------------
	// Catch-all (Symbols: nil) so every reference — including type uses like
	// `*mlkem.DecapsulationKey768` — gets recorded into the analyzer result
	// for CBOM. INFO findings are filtered out by DiagnosticReporter, so the
	// developer is not nagged about correctly-chosen PQC algorithms.
	//
	// Purpose=KeyExchange is correct for every symbol crypto/mlkem currently
	// exports. If the package ever grows non-keyex symbols, this catch-all
	// must be narrowed to specific symbols (or split into purpose-tagged
	// entries) to avoid mislabeling.
	//
	// crypto/mldsa is not yet in the standard library as of Go 1.26.2; a rule
	// will be added once it ships (or for a third-party implementation like
	// filippo.io/mldsa) in a later milestone.
	{
		// OID is the NIST KEM arc (2.16.840.1.101.3.4.4) — sufficient for v1
		// since the rule is catch-all. A future CBOM will likely want the
		// per-parameter-set OIDs: ML-KEM-512=...4.1, ML-KEM-768=...4.2,
		// ML-KEM-1024=...4.3. That requires splitting the rule into
		// symbol-specific entries (GenerateKey512/768/1024).
		Pkg:       "crypto/mlkem",
		Symbols:   nil,
		Exposure:  finding.ExposureSafe,
		Purpose:   finding.PurposeKeyExchange,
		Algorithm: "ML-KEM",
		OID:       "2.16.840.1.101.3.4.4",
	},
}
