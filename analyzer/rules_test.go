package analyzer

import "testing"

// TestMatchFirstWins guards the ordering contract: when a package has both
// a specific-symbol rule and a catch-all rule, the specific rule must win.
// Today no package has both, so the contract is latent — this test pins it
// so a future catch-all entry can't silently shadow a specific rule.
func TestMatchFirstWins(t *testing.T) {
	tbl := []Rule{
		{Pkg: "fake/pkg", Symbols: []string{"Special"}, Algorithm: "Specific"},
		{Pkg: "fake/pkg", Symbols: nil, Algorithm: "CatchAll"},
	}

	got, ok := matchFirst(tbl, "fake/pkg", "Special")
	if !ok {
		t.Fatal("Special should match")
	}
	if got.Algorithm != "Specific" {
		t.Errorf("specific rule must win, got %q", got.Algorithm)
	}

	got, ok = matchFirst(tbl, "fake/pkg", "Other")
	if !ok {
		t.Fatal("catch-all should match unknown symbol")
	}
	if got.Algorithm != "CatchAll" {
		t.Errorf("catch-all expected for unknown symbol, got %q", got.Algorithm)
	}

	if _, ok := matchFirst(tbl, "other/pkg", "Special"); ok {
		t.Error("rule from different package must not match")
	}
}
