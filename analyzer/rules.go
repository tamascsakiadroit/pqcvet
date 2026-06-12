package analyzer

import "pqcvet/finding"

// Rule describes one cryptographic-asset detection. Rules are matched by
// resolved package import path plus symbol name, never by string-matching
// identifiers — so import aliasing is handled correctly.
//
// An empty Symbols slice means "match any symbol from this package."
//
// Severity, if non-empty, overrides the result of classify(Exposure, Purpose).
// Use it for algorithms whose true risk doesn't fit the matrix — e.g.
// classically-broken hashes (MD5, SHA-1) that deserve more than Grover-LOW.
type Rule struct {
	Pkg         string
	Symbols     []string
	Exposure    finding.Exposure
	Purpose     finding.Purpose
	Severity    finding.Severity // optional override; zero value = use classify()
	Algorithm   string
	OID         string
	Remediation string
}

func (r Rule) matches(pkg, symbol string) bool {
	if r.Pkg != pkg {
		return false
	}
	if len(r.Symbols) == 0 {
		return true
	}
	for _, s := range r.Symbols {
		if s == symbol {
			return true
		}
	}
	return false
}

// matchFirst returns the first rule in tbl whose package + symbol pair matches.
// First-match-wins matters once a package has both a specific-symbol rule and
// a catch-all (Symbols: nil) entry — the specific rule must be listed first.
//
// O(N) scan is fine for now: the table has ~14 entries and each call runs
// once per identifier walked by the analyzer. The ident-walk visits roughly
// 5-10× more nodes than the old selector-walk did, but the per-call cost is
// still a handful of string comparisons. A map[pkg][]Rule index becomes
// worthwhile if the table grows past ~50 entries or the analyzer gets run
// on hot paths.
func matchFirst(tbl []Rule, pkg, symbol string) (Rule, bool) {
	for _, r := range tbl {
		if r.matches(pkg, symbol) {
			return r, true
		}
	}
	return Rule{}, false
}

// lookupRule is the package-level convenience that scans the embedded table.
func lookupRule(pkg, symbol string) (Rule, bool) {
	return matchFirst(rules, pkg, symbol)
}
