package analyzer

import (
	"testing"

	"pqcvet/finding"
)

// TestClassifyMatrix pins every cell of the severity matrix independently of
// which rules currently exist — Grover/Safe branches have no rules yet, so
// without this test they would be unreachable from analysistest alone.
func TestClassifyMatrix(t *testing.T) {
	cases := []struct {
		exp  finding.Exposure
		purp finding.Purpose
		want finding.Severity
	}{
		// shor — asymmetric
		{finding.ExposureShor, finding.PurposeKeyExchange, finding.SeverityHigh},
		{finding.ExposureShor, finding.PurposeEncryption, finding.SeverityHigh},
		{finding.ExposureShor, finding.PurposeSignature, finding.SeverityMedium},

		// grover — symmetric/hash
		{finding.ExposureGrover, finding.PurposeSymmetric, finding.SeverityLow},
		{finding.ExposureGrover, finding.PurposeHashing, finding.SeverityLow},

		// safe — PQC, recorded only
		{finding.ExposureSafe, finding.PurposeKeyExchange, finding.SeverityInfo},
		{finding.ExposureSafe, finding.PurposeSignature, finding.SeverityInfo},
		{finding.ExposureSafe, finding.PurposeEncryption, finding.SeverityInfo},

		// "n/a" cells — misconfigured-rule sentinel. Must collapse to INFO so
		// a bad rule cannot surface a high-confidence severity it hasn't earned.
		{finding.ExposureShor, finding.PurposeSymmetric, finding.SeverityInfo},
		{finding.ExposureShor, finding.PurposeHashing, finding.SeverityInfo},
		{finding.ExposureGrover, finding.PurposeKeyExchange, finding.SeverityInfo},
		{finding.ExposureGrover, finding.PurposeSignature, finding.SeverityInfo},

		// classical — matrix has no cells; rules must carry a Severity override.
		// Without one, classify falls through to INFO (visible misconfig).
		{finding.ExposureClassical, finding.PurposeHashing, finding.SeverityInfo},
		{finding.ExposureClassical, finding.PurposeSymmetric, finding.SeverityInfo},
	}
	for _, tc := range cases {
		got := classify(tc.exp, tc.purp)
		if got != tc.want {
			t.Errorf("classify(%s, %s) = %s, want %s", tc.exp, tc.purp, got, tc.want)
		}
	}
}

// TestSelectSeverityOverride pins the contract that Rule.Severity wins over
// the matrix when set — used for algorithms whose true risk doesn't fit
// (e.g. classically-broken hashes deserving more than Grover-LOW).
func TestSelectSeverityOverride(t *testing.T) {
	// Override present: matrix would say LOW, override forces HIGH.
	override := Rule{
		Exposure: finding.ExposureGrover,
		Purpose:  finding.PurposeHashing,
		Severity: finding.SeverityHigh,
	}
	if got := selectSeverity(override); got != finding.SeverityHigh {
		t.Errorf("override should win: got %s, want HIGH", got)
	}

	// No override: matrix decides.
	matrix := Rule{
		Exposure: finding.ExposureShor,
		Purpose:  finding.PurposeSignature,
	}
	if got := selectSeverity(matrix); got != finding.SeverityMedium {
		t.Errorf("matrix should decide when no override: got %s, want MEDIUM", got)
	}
}
