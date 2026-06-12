package analyzer

import (
	"strings"
	"testing"

	"github.com/tamascsakiadroit/pqcvet/finding"
)

// TestFormatMessage pins the diagnostic format independently of the
// analysistest fixtures, which only match it via regex. If the format
// changes, both the fixtures and downstream consumers parsing the message
// can be updated deliberately.
func TestFormatMessage(t *testing.T) {
	f := finding.Finding{
		Pkg:         "crypto/rsa",
		Symbol:      "GenerateKey",
		Algorithm:   "RSA",
		Exposure:    finding.ExposureShor,
		Purpose:     finding.PurposeEncryption,
		Severity:    finding.SeverityHigh,
		Remediation: "use ML-KEM",
	}
	got := formatMessage(f)
	want := "pqcvet[HIGH]: crypto/rsa.GenerateKey — RSA (shor, encryption); use ML-KEM"
	if got != want {
		t.Errorf("formatMessage =\n  %q\nwant\n  %q", got, want)
	}

	// Sanity: every field that drives severity/UX must appear.
	for _, sub := range []string{"HIGH", "crypto/rsa", "GenerateKey", "RSA", "shor", "encryption", "ML-KEM"} {
		if !strings.Contains(got, sub) {
			t.Errorf("formatMessage missing %q in %q", sub, got)
		}
	}
}
