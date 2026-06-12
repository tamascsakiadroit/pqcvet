package analyzer

import "pqcvet/finding"

// classify implements the severity matrix from the spec §3:
//
//	exposure × purpose      keyex/encryption     signature       symmetric/hash
//	shor                    HIGH                 MEDIUM          n/a
//	grover                  n/a                  n/a             LOW
//	classical               n/a (override)       n/a (override)  n/a (override)
//	safe                    INFO                 INFO            INFO
//
// Parameter-aware escalation (e.g. "AES-128 → MEDIUM, AES-256 → LOW") is
// deliberately NOT implemented. In idiomatic Go the key passed to
// aes.NewCipher is a runtime []byte whose length is rarely a compile-time
// constant — go/types constant folding can't recover it, so any attempt to
// statically decide key size would mostly produce false positives or false
// negatives. Algorithms that are weak *by identity* (MD5, SHA-1, DES, RC4)
// don't need parameter inspection and are handled via a Rule.Severity override
// (see selectSeverity below). They carry Exposure=classical so downstream
// consumers see the real risk vector; the matrix has no cells for classical,
// so a missing override would degrade to INFO — the sentinel for misconfig.
//
// RSA bit size IS recoverable when the argument is a literal
// (`rsa.GenerateKey(rand, 2048)`), but irrelevant to the PQC severity model:
// RSA-2048 and RSA-4096 are both Shor-broken to the same degree. A
// classical-strength signal could be added orthogonally, outside this matrix.
// "n/a" cells (Shor + symmetric/hashing, Grover + asymmetric purposes) fall
// through to SeverityInfo. This is a misconfigured-rule sentinel: a rule
// landing here will appear in the JSON result as Info (so a maintainer sees
// the anomaly) but will not surface as a diagnostic claiming a confidence
// level the matrix doesn't actually support.
func classify(exp finding.Exposure, purp finding.Purpose) finding.Severity {
	switch exp {
	case finding.ExposureShor:
		switch purp {
		case finding.PurposeKeyExchange, finding.PurposeEncryption:
			return finding.SeverityHigh
		case finding.PurposeSignature:
			return finding.SeverityMedium
		}
		return finding.SeverityInfo

	case finding.ExposureGrover:
		switch purp {
		case finding.PurposeHashing, finding.PurposeSymmetric:
			return finding.SeverityLow
		}
		return finding.SeverityInfo

	case finding.ExposureSafe:
		return finding.SeverityInfo
	}
	return finding.SeverityInfo
}

// selectSeverity applies a rule-level Severity override if set; otherwise
// derives the severity from the (Exposure, Purpose) matrix. Used by run().
func selectSeverity(r Rule) finding.Severity {
	if r.Severity != "" {
		return r.Severity
	}
	return classify(r.Exposure, r.Purpose)
}
