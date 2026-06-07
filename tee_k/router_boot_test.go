package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	base := TEEKConfig{
		RouterURL:               "https://router",
		SelfAddr:                "10.0.0.1:443",
		PeerAddr:                "10.0.0.2:443",
		ExpectedPeerImageDigest: "sha256:abc",
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

// fakeRouter is a minimal stand-in for the multi-pair router: counts
// heartbeats/registers, and can be told to 404 the first heartbeat to
// exercise the re-register path.
type fakeRouter struct {
	mu                sync.Mutex
	heartbeats        int
	registers         int
	heartbeat404Until int // 404 the first N heartbeats
}

func (f *fakeRouter) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/register":
			f.registers++
			_ = json.NewEncoder(w).Encode(shared.RegisterResponse{
				PairID: "test-pair", Status: "registering",
			})
		case "/heartbeat":
			f.heartbeats++
			if f.heartbeats <= f.heartbeat404Until {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(shared.HeartbeatResponse{
				PairID: "test-pair", Status: "degraded",
			})
		default:
			http.Error(w, "unknown path", http.StatusNotFound)
		}
	}
}

func (f *fakeRouter) snapshot() (heartbeats, registers int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats, f.registers
}

func newFakeRouter() (*fakeRouter, *httptest.Server) {
	f := &fakeRouter{}
	return f, httptest.NewServer(f.handler())
}

// minimalTEEK builds just enough of a TEEK for runHeartbeats to read its
// router-mode fields. The full TEEK constructor pulls in attestation +
// session-manager state that the heartbeat loop doesn't touch.
func minimalTEEK(router *shared.RouterClient, pairID string) *TEEK {
	return &TEEK{router: router, pairID: pairID}
}

func TestRunHeartbeats_SendsPeriodically(t *testing.T) {
	f, srv := newFakeRouter()
	t.Cleanup(srv.Close)

	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := shared.NewRouterClient(srv.URL, tokens)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	teek := minimalTEEK(router, "test-pair")
	done := make(chan struct{})
	go func() {
		runHeartbeats(ctx, teek, "K",
			shared.GetTEEKLogger(),
			func(_ context.Context) error { return nil },
			5*time.Millisecond)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	hb, regs := f.snapshot()
	if hb < 3 {
		t.Fatalf("expected at least 3 heartbeats in 30ms@5ms, got %d", hb)
	}
	if regs != 0 {
		t.Fatalf("expected no re-registers when heartbeats succeed, got %d", regs)
	}
}

func TestRunHeartbeats_ReregistersOn404(t *testing.T) {
	f, srv := newFakeRouter()
	f.heartbeat404Until = 1 // only the very first heartbeat 404s
	t.Cleanup(srv.Close)

	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := shared.NewRouterClient(srv.URL, tokens)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	var reregisterCalls atomic.Int32
	onLost := func(_ context.Context) error {
		reregisterCalls.Add(1)
		return nil
	}

	teek := minimalTEEK(router, "test-pair")
	done := make(chan struct{})
	go func() {
		runHeartbeats(ctx, teek, "K",
			shared.GetTEEKLogger(),
			onLost, 5*time.Millisecond)
		close(done)
	}()

	time.Sleep(40 * time.Millisecond)
	cancel()
	<-done

	if got := reregisterCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 re-register triggered by 404, got %d", got)
	}
	hb, _ := f.snapshot()
	if hb < 3 {
		t.Fatalf("expected heartbeats to keep firing after 404, got %d", hb)
	}
}

func TestRunHeartbeats_ContextCancelStops(t *testing.T) {
	_, srv := newFakeRouter()
	t.Cleanup(srv.Close)

	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := shared.NewRouterClient(srv.URL, tokens)

	ctx, cancel := context.WithCancel(t.Context())
	teek := minimalTEEK(router, "p")
	done := make(chan struct{})
	go func() {
		runHeartbeats(ctx, teek, "K",
			shared.GetTEEKLogger(),
			func(_ context.Context) error { return nil },
			50*time.Millisecond)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// expected
	case <-time.After(time.Second):
		t.Fatal("runHeartbeats did not return within 1s of context cancel")
	}
}
