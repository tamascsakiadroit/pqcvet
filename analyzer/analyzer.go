// Package analyzer implements the pqcvet go/analysis analyzer.
//
// It walks every selector expression in the type-checked AST, resolves the
// referenced object to its real import path + symbol name (so import aliases
// are transparent), and looks the pair up in the rule table. Matches become
// Finding values, classified by the severity matrix in classify.go (or by an
// explicit Rule.Severity override). Findings are forwarded to a Reporter
// (the default DiagnosticReporter emits go/analysis diagnostics) and the
// full slice is returned as the analyzer result for downstream consumers
// (e.g. a structured-output driver — see cmd/pqcvet).
package analyzer

import (
	"go/ast"
	"reflect"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"github.com/tamascsakiadroit/pqcvet/finding"
)

// Analyzer.ResultType is part of the public contract: the JSON driver (and
// any other go/analysis caller using checker.Analyze) reads each action's
// Result as []finding.Finding. Keep the declared type and the run() return
// shape in sync.
var Analyzer = &analysis.Analyzer{
	Name:       "pqcvet",
	Doc:        "flags quantum-vulnerable cryptography usage and records cryptographic assets",
	Requires:   []*analysis.Analyzer{inspect.Analyzer},
	Run:        run,
	ResultType: reflect.TypeOf([]finding.Finding(nil)),
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	reporter := &DiagnosticReporter{Pass: pass}

	// Walk every identifier rather than just SelectorExpr.Sel — this covers
	// dot-imported call sites (e.g. `import . "crypto/rsa"; GenerateKey(...)`),
	// which are otherwise invisible to a selector-only walk. Package-name
	// idents resolve to *types.PkgName whose Pkg() is the importing package,
	// so they never match a rule and don't create false positives.
	var findings []finding.Finding
	insp.Preorder([]ast.Node{(*ast.Ident)(nil)}, func(n ast.Node) {
		ident := n.(*ast.Ident)
		obj := pass.TypesInfo.ObjectOf(ident)
		if obj == nil || obj.Pkg() == nil {
			return
		}
		rule, ok := lookupRule(obj.Pkg().Path(), obj.Name())
		if !ok {
			return
		}

		f := finding.Finding{
			Pkg:         obj.Pkg().Path(),
			Symbol:      obj.Name(),
			Algorithm:   rule.Algorithm,
			OID:         rule.OID,
			Exposure:    rule.Exposure,
			Purpose:     rule.Purpose,
			Severity:    selectSeverity(rule),
			Remediation: rule.Remediation,
			Pos:         pass.Fset.Position(ident.Pos()),
		}
		findings = append(findings, f)
		reporter.Report(f, ident.Pos())
	})
	return findings, nil
}
