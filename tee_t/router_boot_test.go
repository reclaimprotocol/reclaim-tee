package main

import (
	"strings"
	"testing"
)

func TestTEETConfig_RouterModeDetection(t *testing.T) {
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
			c := &TEETConfig{RouterURL: tc.routerURL}
			if got := c.RouterMode(); got != tc.want {
				t.Fatalf("RouterMode() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateRouterConfig(t *testing.T) {
	base := TEETConfig{
		RouterURL:               "https://router",
		SelfAddr:                "10.0.0.2:443",
		PeerAddr:                "10.0.0.1:443",
		ExpectedPeerImageDigest: "sha256:abc",
		JWTPublicKey:            "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
	}
	if err := validateRouterConfig(&base); err != nil {
		t.Fatalf("full config should validate: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*TEETConfig)
		want   string
	}{
		{"missing SELF_ADDR", func(c *TEETConfig) { c.SelfAddr = "" }, "SELF_ADDR"},
		{"missing PEER_ADDR", func(c *TEETConfig) { c.PeerAddr = "" }, "PEER_ADDR"},
		{"missing EXPECTED_PEER_IMAGE_DIGEST", func(c *TEETConfig) { c.ExpectedPeerImageDigest = "" }, "EXPECTED_PEER_IMAGE_DIGEST"},
		{"missing JWT_PUBLIC_KEY", func(c *TEETConfig) { c.JWTPublicKey = "" }, "JWT_PUBLIC_KEY"},
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
