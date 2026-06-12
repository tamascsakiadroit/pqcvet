package main

import (
	"fmt"
	"go/token"
	"os"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	"github.com/tamascsakiadroit/pqcvet/analyzer"
	"github.com/tamascsakiadroit/pqcvet/finding"
)

// Report is the top-level JSON payload. Envelope kept thin on purpose so a
// future "schema" / "tool" / CBOM metadata block can be added without breaking
// downstream consumers.
type Report struct {
	Findings []AggregatedFinding `json:"findings"`
}

// AggregatedFinding deduplicates many per-call-site Findings that share the
// same (Pkg, Symbol, Algorithm) tuple. Per anti-goal #4 in the refactor plan,
// the text/diagnostic path stays per-call-site — aggregation lives in JSON
// (and future CBOM) output only.
type AggregatedFinding struct {
	Pkg         string           `json:"pkg"`
	Symbol      string           `json:"symbol"`
	Algorithm   string           `json:"algorithm"`
	OID         string           `json:"oid,omitempty"`
	Exposure    finding.Exposure `json:"exposure"`
	Purpose     finding.Purpose  `json:"purpose"`
	Severity    finding.Severity `json:"severity"`
	Remediation string           `json:"remediation,omitempty"`
	Count       int              `json:"count"`
	Positions   []Position       `json:"positions"`
}

// Position is a source location with lowercase JSON tags. token.Position
// marshals with capitalized keys and an Offset field that consumers don't
// need; this local type keeps the report schema stable and tidy.
type Position struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

func toPosition(p token.Position) Position {
	return Position{File: p.Filename, Line: p.Line, Column: p.Column}
}

// runJSON loads `patterns`, runs the analyzer on each loaded package via the
// go/analysis checker driver, and returns the aggregated report plus a flag
// indicating whether any package failed to load. Callers use the flag to
// decide exit code: partial output is still emitted so the report stays
// useful, but downstream CI can distinguish "ran cleanly" from "ran past
// broken packages".
func runJSON(patterns []string) (Report, bool, error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	// checker.Analyze requires LoadAllSyntax-equivalent mode; it panics
	// otherwise.
	cfg := &packages.Config{Mode: packages.LoadAllSyntax}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return Report{}, false, err
	}

	hadPackageErrors := false
	for _, pkg := range pkgs {
		for _, e := range pkg.Errors {
			hadPackageErrors = true
			fmt.Fprintln(os.Stderr, e)
		}
	}

	// checker.Analyze handles Requires (and would handle FactTypes if we
	// grew any) for us. Without it the driver would have to construct the
	// analysis.Pass by hand and recreate the ResultOf map any time
	// analyzer.Analyzer.Requires changed — a quiet footgun.
	graph, err := checker.Analyze([]*analysis.Analyzer{analyzer.Analyzer}, pkgs, nil)
	if err != nil {
		return Report{}, hadPackageErrors, err
	}

	var all []finding.Finding
	for _, act := range graph.Roots {
		if act.Err != nil {
			hadPackageErrors = true
			fmt.Fprintln(os.Stderr, fmt.Errorf("analyze %s: %w", act.Package.PkgPath, act.Err))
			continue
		}
		finds, _ := act.Result.([]finding.Finding)
		all = append(all, finds...)
	}
	return Report{Findings: aggregate(all)}, hadPackageErrors, nil
}

// aggregate buckets findings by (Pkg, Symbol, Algorithm) while preserving
// the order of first appearance, so JSON output is deterministic.
func aggregate(in []finding.Finding) []AggregatedFinding {
	type key struct{ pkg, sym, algo string }
	bucket := map[key]*AggregatedFinding{}
	order := []key{}
	for _, f := range in {
		k := key{f.Pkg, f.Symbol, f.Algorithm}
		if a, ok := bucket[k]; ok {
			a.Count++
			a.Positions = append(a.Positions, toPosition(f.Pos))
			continue
		}
		a := &AggregatedFinding{
			Pkg: f.Pkg, Symbol: f.Symbol, Algorithm: f.Algorithm, OID: f.OID,
			Exposure: f.Exposure, Purpose: f.Purpose, Severity: f.Severity,
			Remediation: f.Remediation,
			Count:       1,
			Positions:   []Position{toPosition(f.Pos)},
		}
		bucket[k] = a
		order = append(order, k)
	}
	out := make([]AggregatedFinding, 0, len(order))
	for _, k := range order {
		out = append(out, *bucket[k])
	}
	return out
}
