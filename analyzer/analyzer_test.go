package analyzer_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/tamascsakiadroit/pqcvet/analyzer"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), analyzer.Analyzer,
		"rsa_basic",
		"rsa_parsed",
		"ecdsa_basic",
		"ed25519_basic",
		"mlkem_safe",
		"alias",
		"dot_import",
		"signer_method",
		"signer_iface",
		"grover_weak",
		"crypto_hash",
		"ecdh_basic",
		"dsa_basic",
	)
}
