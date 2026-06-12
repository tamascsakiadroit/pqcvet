package analyzer

import (
	"fmt"
	"go/token"

	"golang.org/x/tools/go/analysis"

	"github.com/tamascsakiadroit/pqcvet/finding"
)

// formatMessage builds the linter-facing message from a Finding. Centralized
// so any future reporter (JSON, CBOM) reuses the underlying field data instead
// of re-parsing a pre-rendered string.
func formatMessage(f finding.Finding) string {
	return fmt.Sprintf(
		"pqcvet[%s]: %s.%s — %s (%s, %s); %s",
		f.Severity, f.Pkg, f.Symbol,
		f.Algorithm, f.Exposure, f.Purpose,
		f.Remediation,
	)
}

// DiagnosticReporter is the default Reporter used inside the go/analysis pass.
// Safe (PQC) findings are recorded in the analyzer result but NOT emitted as
// diagnostics — we don't nag developers about correctly-chosen post-quantum
// algorithms.
type DiagnosticReporter struct {
	Pass *analysis.Pass
}

func (d *DiagnosticReporter) Report(f finding.Finding, pos token.Pos) {
	if f.Exposure == finding.ExposureSafe || f.Severity == finding.SeverityInfo {
		return
	}
	d.Pass.Report(analysis.Diagnostic{
		Pos:     pos,
		Message: formatMessage(f),
	})
}
