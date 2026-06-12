package finding

import "go/token"

// Exposure is the cryptographic-weakness vector that applies to an algorithm.
// Most are quantum-related (shor, grover, safe); classical covers algorithms
// already broken without quantum help.
type Exposure string

const (
	ExposureShor      Exposure = "shor"      // asymmetric, broken outright by Shor
	ExposureGrover    Exposure = "grover"    // symmetric/hash, quadratically weakened by Grover
	ExposureClassical Exposure = "classical" // already broken by classical attacks (MD5, SHA-1, DES, RC4)
	ExposureSafe      Exposure = "safe"      // PQC algorithm or hybrid construction
)

// Purpose is what the algorithm is being used for. Drives severity because
// of harvest-now-decrypt-later: keyexchange/encryption captured today is
// decryptable later, signatures are not.
type Purpose string

const (
	PurposeKeyExchange Purpose = "keyexchange"
	PurposeEncryption  Purpose = "encryption"
	PurposeSignature   Purpose = "signature"
	PurposeHashing     Purpose = "hashing"
	PurposeSymmetric   Purpose = "symmetric"
)

// Severity is the linter-facing severity level.
type Severity string

const (
	SeverityInfo   Severity = "INFO"
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Finding is a single detected use of a cryptographic algorithm.
type Finding struct {
	Pkg         string
	Symbol      string
	Algorithm   string
	OID         string
	Exposure    Exposure
	Purpose     Purpose
	Severity    Severity
	Remediation string
	Pos         token.Position
}
