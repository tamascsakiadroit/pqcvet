package main

import (
	"go/token"
	"testing"

	"github.com/tamascsakiadroit/pqcvet/finding"
)

func TestExtractFormat(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantFormat string
		wantRest   []string
		wantErr    bool
	}{
		{"none", []string{"./..."}, "", []string{"./..."}, false},
		{"equals", []string{"-format=json", "./..."}, "json", []string{"./..."}, false},
		{"space", []string{"-format", "json", "./..."}, "json", []string{"./..."}, false},
		{"double-dash", []string{"--format=text", "./..."}, "text", []string{"./..."}, false},
		{"between", []string{"./...", "-format", "json", "./pkg"}, "json", []string{"./...", "./pkg"}, false},
		{"missing-value", []string{"-format"}, "", nil, true},
		{"missing-value-trailing", []string{"./...", "--format"}, "", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, r, err := extractFormat(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if f != tc.wantFormat {
				t.Errorf("format = %q, want %q", f, tc.wantFormat)
			}
			if !equal(r, tc.wantRest) {
				t.Errorf("rest = %v, want %v", r, tc.wantRest)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAggregate(t *testing.T) {
	mk := func(pkg, sym, algo string, line int) finding.Finding {
		return finding.Finding{
			Pkg: pkg, Symbol: sym, Algorithm: algo,
			Exposure: finding.ExposureShor, Purpose: finding.PurposeSignature,
			Severity: finding.SeverityMedium,
			Pos:      token.Position{Filename: "x.go", Line: line, Column: 1},
		}
	}
	in := []finding.Finding{
		mk("crypto/rsa", "GenerateKey", "RSA", 10),
		mk("crypto/rsa", "GenerateKey", "RSA", 20), // dup → bumps Count
		mk("crypto/ecdsa", "Sign", "ECDSA", 30),
		mk("crypto/rsa", "GenerateKey", "RSA", 40), // dup again
	}
	out := aggregate(in)

	if len(out) != 2 {
		t.Fatalf("got %d aggregated, want 2", len(out))
	}

	// Order of first appearance must be preserved.
	if out[0].Algorithm != "RSA" {
		t.Errorf("out[0] = %q, want RSA (first seen)", out[0].Algorithm)
	}
	if out[1].Algorithm != "ECDSA" {
		t.Errorf("out[1] = %q, want ECDSA", out[1].Algorithm)
	}

	if out[0].Count != 3 || len(out[0].Positions) != 3 {
		t.Errorf("RSA count/positions = %d/%d, want 3/3", out[0].Count, len(out[0].Positions))
	}
	if out[1].Count != 1 || len(out[1].Positions) != 1 {
		t.Errorf("ECDSA count/positions = %d/%d, want 1/1", out[1].Count, len(out[1].Positions))
	}

	// Position lines come back in input order — 10, 20, 40.
	wantLines := []int{10, 20, 40}
	for i, p := range out[0].Positions {
		if p.Line != wantLines[i] {
			t.Errorf("RSA positions[%d] line = %d, want %d", i, p.Line, wantLines[i])
		}
	}
}

func TestRunJSONOnTestdata(t *testing.T) {
	report, hadPackageErrors, err := runJSON([]string{"../../analyzer/testdata/src/rsa_basic"})
	if err != nil {
		t.Fatalf("runJSON: %v", err)
	}
	if hadPackageErrors {
		t.Errorf("expected clean load, got hadPackageErrors=true")
	}
	// rsa_basic has GenerateKey, SignPKCS1v15, and EncryptOAEP — 3 distinct symbols.
	if len(report.Findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(report.Findings), report.Findings)
	}
	for _, f := range report.Findings {
		if f.Algorithm != "RSA" {
			t.Errorf("expected Algorithm=RSA, got %q", f.Algorithm)
		}
		if f.Count != 1 {
			t.Errorf("rsa_basic uses each symbol once; got Count=%d for %s", f.Count, f.Symbol)
		}
		if len(f.Positions) != 1 || f.Positions[0].Line == 0 || f.Positions[0].File == "" {
			t.Errorf("Position should be filled in for %s, got %+v", f.Symbol, f.Positions)
		}
	}
}

func TestReportHasFindings(t *testing.T) {
	mk := func(sev finding.Severity) AggregatedFinding {
		return AggregatedFinding{Severity: sev}
	}

	cases := []struct {
		name   string
		report Report
		want   bool
	}{
		{"empty", Report{}, false},
		{"only-info", Report{Findings: []AggregatedFinding{mk(finding.SeverityInfo)}}, false},
		{"has-medium", Report{Findings: []AggregatedFinding{mk(finding.SeverityInfo), mk(finding.SeverityMedium)}}, true},
		{"has-high", Report{Findings: []AggregatedFinding{mk(finding.SeverityHigh)}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reportHasFindings(tc.report); got != tc.want {
				t.Errorf("reportHasFindings = %v, want %v", got, tc.want)
			}
		})
	}
}
