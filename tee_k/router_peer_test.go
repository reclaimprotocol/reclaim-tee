package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
)

// acceptAnyPeer is the test verifier: returns nil regardless of what the
// server presented. Lets us exercise the dial/handshake/read-loop path
// without needing a real GCP attestation in the server cert.
func acceptAnyPeer(_ [][]byte, _ [][]*x509.Certificate) error { return nil }

// newPeerWSServer starts an httptest TLS server that accepts WebSocket
// upgrades at /ws/peer. The closeImmediately flag controls whether the
// server closes the connection right after upgrade or holds it open until
// the test tears down.
func newPeerWSServer(t *testing.T, closeImmediately bool) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool { return true },
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws/peer" {
			http.NotFound(w, r)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if closeImmediately {
			_ = conn.Close()
			return
		}
		// Block reading until client disconnects or server is torn down.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// addrOf returns "host:port" from an httptest.Server's URL — the form
// runPeerConnection wants in peerAddr.
func addrOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	url := strings.TrimPrefix(srv.URL, "https://")
	host, port, err := net.SplitHostPort(url)
	if err != nil {
		t.Fatalf("split host:port from %q: %v", url, err)
	}
	return net.JoinHostPort(host, port)
}

// waitForState polls state until the predicate is true or timeout fires.
// Eliminates the "did the goroutine have time to run yet?" coin-flip that
// time.Sleep-based tests suffer from.
func waitForState(t *testing.T, pred func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestRunPeerConnection_FlipsHealthyOnConnect(t *testing.T) {
	srv := newPeerWSServer(t, false)
	state := &heartbeatState{}
	tlsConfig := &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: acceptAnyPeer,
		MinVersion:            tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		runPeerConnection(ctx, addrOf(t, srv), tlsConfig, state, shared.GetTEEKLogger())
		close(done)
	}()

	waitForState(t, func() bool { return state.controlHealthy.Load() },
		2*time.Second, "controlHealthy never flipped to true after server became reachable")

	cancel()
	<-done
	if state.controlHealthy.Load() {
		t.Fatal("controlHealthy should be false after shutdown")
	}
}

func TestRunPeerConnection_FlipsUnhealthyOnDisconnect(t *testing.T) {
	// Server accepts the upgrade then immediately closes. Verifies that
	// runPeerConnection notices the disconnect and reflects it in state.
	srv := newPeerWSServer(t, true)
	state := &heartbeatState{}
	state.controlHealthy.Store(true) // pretend a previous connection was healthy
	tlsConfig := &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: acceptAnyPeer,
		MinVersion:            tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		runPeerConnection(ctx, addrOf(t, srv), tlsConfig, state, shared.GetTEEKLogger())
		close(done)
	}()

	// The connection cycles: connect → server closes → state false →
	// backoff → connect again. We just want to see at least one false-flip
	// after the goroutine has had a chance to connect+disconnect.
	waitForState(t, func() bool {
		// The connection MAY briefly be true between connect and close;
		// what we care about is that state oscillates and is observably
		// false at SOME point.
		return !state.controlHealthy.Load()
	}, 2*time.Second, "controlHealthy never observed as false after disconnect cycle")

	cancel()
	<-done
}

func TestRunPeerConnection_StaysUnhealthyWhenUnreachable(t *testing.T) {
	// Reserve a port without binding it — dial should fail.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	state := &heartbeatState{}
	tlsConfig := &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: acceptAnyPeer,
		MinVersion:            tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		runPeerConnection(ctx, addr, tlsConfig, state, shared.GetTEEKLogger())
		close(done)
	}()

	// Give the dial a chance to fail. State must stay false throughout.
	time.Sleep(50 * time.Millisecond)
	if state.controlHealthy.Load() {
		t.Fatal("controlHealthy should stay false when peer is unreachable")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runPeerConnection did not return within 1s of cancel")
	}
}

func TestSleepCtx(t *testing.T) {
	t.Run("returns false after duration", func(t *testing.T) {
		start := time.Now()
		if got := sleepCtx(t.Context(), 20*time.Millisecond); got {
			t.Fatal("expected false (timer fired, not cancelled)")
		}
		if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
			t.Fatalf("returned too early: %v", elapsed)
		}
	})

	t.Run("returns true on context cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var got atomic.Bool
		done := make(chan struct{})
		go func() {
			got.Store(sleepCtx(ctx, time.Hour))
			close(done)
		}()
		// Cancel and expect prompt return.
		time.Sleep(5 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("sleepCtx did not return within 1s of cancel")
		}
		if !got.Load() {
			t.Fatal("expected true (cancelled, not timer)")
		}
	})
}

func TestBuildPeerTLSConfig(t *testing.T) {
	// Construct a config and verify the callbacks are wired the way the
	// runPeerConnection contract assumes.
	ratls, err := shared.NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new ratls: %v", err)
	}

	var verifierCalls atomic.Int32
	verifier := func(_ [][]byte, _ [][]*x509.Certificate) error {
		verifierCalls.Add(1)
		return nil
	}
	cfg := buildPeerTLSConfig(verifier, ratls)

	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must be true — the custom verifier is what enforces RA-TLS")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate must be set so it actually runs")
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate must be set for mTLS")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatal("MinVersion must be at least TLS 1.2")
	}

	// Call through to confirm the wiring lands at the supplied verifier.
	_ = cfg.VerifyPeerCertificate(nil, nil)
	if verifierCalls.Load() != 1 {
		t.Fatal("VerifyPeerCertificate did not route to the supplied verifier")
	}

	// Confirm GetClientCertificate yields the current RA-TLS cert (proves
	// the callback is bound to the manager, not a snapshot).
	cert, err := cfg.GetClientCertificate(nil)
	if err != nil || cert == nil {
		t.Fatalf("GetClientCertificate: cert=%v err=%v", cert, err)
	}
}
