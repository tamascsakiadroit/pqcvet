// Command pqcvet flags quantum-vulnerable cryptography in Go code.
//
// Default usage is a vet-style linter:
//
//	pqcvet ./...
//
// behaves like go vet, prints diagnostics, composes with go/analysis-based
// pipelines such as golangci-lint.
//
// For structured output, pass -format json:
//
//	pqcvet -format json ./...
//
// In JSON mode the binary runs the analyzer over the loaded packages and
// writes a single aggregated report to stdout. Findings are deduplicated by
// (package, symbol, algorithm) and each entry carries a count + every
// matching source position. JSON mode is implemented via a custom driver
// because singlechecker.Main discards the analyzer's return value.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/tamascsakiadroit/pqcvet/analyzer"
	"github.com/tamascsakiadroit/pqcvet/finding"
)

// Exit codes intentionally mirror singlechecker / go vet so JSON and text
// modes are interchangeable from CI's perspective:
//
//	0 — no findings, clean run
//	1 — at least one package failed to load (partial output still emitted)
//	2 — internal error (bad flag, JSON encode failure, analyzer error)
//	3 — findings present
//
// When both findings and package errors occur, findings take precedence.
const (
	exitFindings      = 3
	exitInternalError = 2
	exitPackageError  = 1
)

func main() {
	args := os.Args[1:]
	format, rest, err := extractFormat(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqcvet:", err)
		os.Exit(exitInternalError)
	}
	switch format {
	case "", "text":
		os.Args = append([]string{os.Args[0]}, rest...)
		singlechecker.Main(analyzer.Analyzer)
	case "json":
		report, hadPackageErrors, err := runJSON(rest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pqcvet:", err)
			os.Exit(exitInternalError)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, "pqcvet:", err)
			os.Exit(exitInternalError)
		}
		if reportHasFindings(report) {
			os.Exit(exitFindings)
		}
		if hadPackageErrors {
			os.Exit(exitPackageError)
		}
	default:
		fmt.Fprintf(os.Stderr, "pqcvet: unknown -format %q (want \"text\" or \"json\")\n", format)
		os.Exit(exitInternalError)
	}
}

// reportHasFindings returns true if the report contains any non-INFO entry.
// Safe (PQC) findings carry Severity=INFO and are recorded for CBOM but
// must not influence exit code — they aren't problems.
func reportHasFindings(r Report) bool {
	for _, f := range r.Findings {
		if f.Severity != finding.SeverityInfo {
			return true
		}
	}
	return false
}

// extractFormat pulls -format=<value> (or --format <value>) out of args
// before singlechecker.Main parses its own flags. Returns the format string
// and the remaining args (in their original order). A trailing -format with
// no value is treated as an error rather than silently degrading to text
// mode — a typo like `-format jsno` is loud; a dropped value should be too.
func extractFormat(args []string) (format string, rest []string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-format" || a == "--format":
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("flag %s requires a value", a)
			}
			format = args[i+1]
			i++
		case strings.HasPrefix(a, "-format="):
			format = strings.TrimPrefix(a, "-format=")
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		default:
			rest = append(rest, a)
		}
	}
	return format, rest, nil
}
