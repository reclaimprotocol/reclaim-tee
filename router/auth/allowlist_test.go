package auth

import "testing"

func TestAllowlist(t *testing.T) {
	a := NewAllowlist([]string{"sha256:aaa", "sha256:bbb"})
	if !a.Contains("sha256:aaa") {
		t.Fatal("expected aaa to be allowed")
	}
	if !a.Contains("sha256:bbb") {
		t.Fatal("expected bbb to be allowed")
	}
	if a.Contains("sha256:ccc") {
		t.Fatal("ccc should not be allowed")
	}
	if a.Contains("") {
		t.Fatal("empty digest should not be allowed")
	}
}

func TestAllowlist_DefensiveCopyOfInput(t *testing.T) {
	// Mutating the input slice after construction must not affect the allowlist.
	approved := []string{"sha256:aaa"}
	a := NewAllowlist(approved)
	approved[0] = "sha256:tampered"
	if !a.Contains("sha256:aaa") {
		t.Fatal("allowlist must not share input slice")
	}
}
