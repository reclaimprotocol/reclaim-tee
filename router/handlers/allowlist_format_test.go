package handlers

import (
	"strings"
	"testing"
)

func TestValidateDigestFormat(t *testing.T) {
	sha := "sha256:" + strings.Repeat("a", 64)
	snp := "snp-pcr:" + strings.Repeat("b", 64)

	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid sha256", sha, true},
		{"valid snp pcr", snp, true},
		{"sha256 wrong length", "sha256:" + strings.Repeat("a", 63), false},
		{"snp wrong length (96 not 64)", "snp-pcr:" + strings.Repeat("b", 96), false},
		{"snp uppercase hex", "snp-pcr:" + strings.Repeat("B", 64), false},
		{"unknown prefix", "snp:" + strings.Repeat("a", 64), false},
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
