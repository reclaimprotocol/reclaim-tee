package main

import (
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestTEEKConfig_RouterModeDetection(t *testing.T) {
	cases := []struct {
		name      string
		routerURL string
		want      bool
	}{
		{"empty → not router mode", "", false},
		{"any value → router mode", "https://tee.reclaimprotocol.org", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &TEEKConfig{RouterURL: tc.routerURL}
			if got := c.RouterMode(); got != tc.want {
				t.Fatalf("RouterMode() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateRouterConfig(t *testing.T) {
	// Base config with everything set; each subtest blanks one field and
	// confirms validation flags it.
	base := TEEKConfig{
		RouterURL:               "https://router",
		SelfAddr:                "10.0.0.1:443",
		PeerAddr:                "10.0.0.2:443",
		ExpectedPeerImageDigest: "sha256:abc",
		SATokenAudience:         "https://router",
		JWTPublicKey:            "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
	}
	if err := validateRouterConfig(&base); err != nil {
		t.Fatalf("full config should validate: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*TEEKConfig)
		want   string
	}{
		{"missing SELF_ADDR", func(c *TEEKConfig) { c.SelfAddr = "" }, "SELF_ADDR"},
		{"missing PEER_ADDR", func(c *TEEKConfig) { c.PeerAddr = "" }, "PEER_ADDR"},
		{"missing EXPECTED_PEER_IMAGE_DIGEST", func(c *TEEKConfig) { c.ExpectedPeerImageDigest = "" }, "EXPECTED_PEER_IMAGE_DIGEST"},
		{"missing SA_TOKEN_AUDIENCE", func(c *TEEKConfig) { c.SATokenAudience = "" }, "SA_TOKEN_AUDIENCE"},
		{"missing JWT_PUBLIC_KEY", func(c *TEEKConfig) { c.JWTPublicKey = "" }, "JWT_PUBLIC_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			err := validateRouterConfig(&c)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestExtractIdentityFromRATLS_StandaloneMode(t *testing.T) {
	// Local dev: no launcher socket → RATLSManager produces a cert without
	// the attestation extension. extractIdentity must fail clearly, not
	// silently return empty strings.
	ratls, err := shared.NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new ratls: %v", err)
	}
	logger := shared.GetTEEKLogger()
	defer logger.Sync()

	_, _, err = extractIdentityFromRATLS(ratls, logger)
	if err == nil {
		t.Fatal("expected error in standalone mode (no attestation extension)")
	}
}
