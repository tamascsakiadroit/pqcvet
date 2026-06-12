package analyzer_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/tamascsakiadroit/pqcvet/analyzer"
	"github.com/tamascsakiadroit/pqcvet/finding"
)

// TestResultRecordsSafe confirms that safe (PQC) algorithm usage is recorded
// in the analyzer's []Finding result while producing NO diagnostic — the
// "recorded but not flagged" contract. analysistest alone can't verify this
// because it only inspects diagnostics, so we read the Result return.
func TestResultRecordsSafe(t *testing.T) {
	results := analysistest.Run(t, analysistest.TestData(), analyzer.Analyzer, "mlkem_safe")
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	res := results[0]

	// 1. No diagnostics expected for a safe-only file.
	if len(res.Diagnostics) != 0 {
		t.Errorf("safe-only file produced %d diagnostics, want 0", len(res.Diagnostics))
	}

	// 2. The Finding for mlkem.GenerateKey768 must be in the result slice,
	// classified as safe / INFO.
	finds, ok := res.Result.([]finding.Finding)
	if !ok {
		t.Fatalf("analyzer Result is %T, want []finding.Finding", res.Result)
	}

	var matched *finding.Finding
	for i := range finds {
		f := &finds[i]
		if f.Pkg == "crypto/mlkem" && f.Symbol == "GenerateKey768" {
			matched = f
			break
		}
	}
	if matched == nil {
		t.Fatalf("expected a Finding for crypto/mlkem.GenerateKey768, got: %+v", finds)
	}
	if matched.Exposure != finding.ExposureSafe {
		t.Errorf("Exposure = %s, want safe", matched.Exposure)
	}
	if matched.Severity != finding.SeverityInfo {
		t.Errorf("Severity = %s, want INFO", matched.Severity)
	}
	if matched.Algorithm != "ML-KEM" {
		t.Errorf("Algorithm = %s, want ML-KEM", matched.Algorithm)
	}
}
