package handlers

import (
	"strings"
	"testing"
)

func TestValidateDigestFormat(t *testing.T) {
	sha := "sha256:" + strings.Repeat("a", 64)
	snp := "snp-measurement:" + strings.Repeat("b", 96)

	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid sha256", sha, true},
		{"valid snp measurement", snp, true},
		{"sha256 wrong length", "sha256:" + strings.Repeat("a", 63), false},
		{"snp wrong length (64 not 96)", "snp-measurement:" + strings.Repeat("b", 64), false},
		{"snp uppercase hex", "snp-measurement:" + strings.Repeat("B", 96), false},
		{"unknown prefix", "snp:" + strings.Repeat("a", 96), false},
		{"no prefix", strings.Repeat("a", 64), false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateDigestFormat(c.in)
			if c.ok && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatalf("expected error for %q, got nil", c.in)
			}
		})
	}
}
