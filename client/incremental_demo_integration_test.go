package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/providers"
)

// TestIncrementalDemoIntegration uses an already running local router, TEE pair,
// and attestor. It is opt-in because it also contacts example.com.
// The target connection wrapper preserves real TLS records and certificates.
func TestIncrementalDemoIntegration(t *testing.T) {
	if os.Getenv("DEMO_INCREMENTAL_TEST") != "1" {
		t.Skip("set DEMO_INCREMENTAL_TEST=1 and DEMO_ROUTER_URL; requires local TEEs and an attestor")
	}
	routerURL := os.Getenv("DEMO_ROUTER_URL")
	if routerURL == "" {
		t.Fatal("DEMO_ROUTER_URL must identify an already running local router")
	}
	if err := requireDemoLoopbackURL(routerURL, "http"); err != nil {
		t.Fatal(err)
	}
	attestorURL := os.Getenv("DEMO_ATTESTOR_URL")
	if attestorURL == "" {
		attestorURL = "ws://localhost:8001/ws"
	}
	if err := requireDemoLoopbackURL(attestorURL, "ws"); err != nil {
		t.Fatal(err)
	}

	responseCase := os.Getenv("DEMO_RESPONSE_CASE")
	if responseCase == "" {
		responseCase = "incremental-delayed-no-eof"
	}
	mode := "incremental"
	var delay time.Duration
	holdEOF, expectTimeout := false, false
	switch responseCase {
	case "incremental-normal":
	case "legacy-normal":
		mode = "legacy"
	case "incremental-delayed-no-eof":
		delay = 6 * time.Second
		holdEOF = true
	case "legacy-no-eof":
		mode, holdEOF, expectTimeout = "legacy", true, true
	default:
		t.Fatalf("unknown DEMO_RESPONSE_CASE %q", responseCase)
	}
	tlsVersion := os.Getenv("DEMO_TLS_VERSION")
	if tlsVersion == "" {
		tlsVersion = "1.3"
	}
	protocolTimeout := 30 * time.Second
	if expectTimeout {
		protocolTimeout = 12 * time.Second
	}
	r, err := NewReclaimClientWithContext(t.Context(), ClientConfig{
		RouterURL: routerURL, AttestorURL: attestorURL, Mode: ModeAuto,
		Timeout: protocolTimeout, ResponseMode: mode,
		ForceTLSVersion: tlsVersion, ForceCipherSuite: os.Getenv("DEMO_CIPHER_SUITE"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	// Native hooks are global. This test and the invoking demo run serially.
	nativeBridgeMutex.RLock()
	oldCheck, oldWS, oldTCP := nativeNetworkCheckFunc, nativeDialWebSocketFunc, nativeDialTCPFunc
	nativeBridgeMutex.RUnlock()
	t.Cleanup(func() { SetNativeNetworkFunctions(oldCheck, oldWS, oldTCP) })
	var target atomic.Pointer[demoResponseConn]
	SetNativeNetworkFunctions(func() bool { return true },
		func(rawURL string, timeoutMS int) (net.Conn, error) {
			if err := requireDemoLoopbackURL(rawURL, "ws"); err != nil {
				return nil, err
			}
			u, err := url.Parse(rawURL)
			if err != nil {
				return nil, err
			}
			return net.DialTimeout("tcp", u.Host, time.Duration(timeoutMS)*time.Millisecond)
		},
		func(address string, timeoutMS int) (net.Conn, error) {
			if address != "example.com:443" {
				return nil, fmt.Errorf("unexpected demo target %q", address)
			}
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutMS)*time.Millisecond)
			if err != nil {
				return nil, err
			}
			wrapped := &demoResponseConn{
				Conn: conn, requestSent: r.Client.httpRequestSent.Load,
				delay: delay, holdEOF: holdEOF, closed: make(chan struct{}),
			}
			target.Store(wrapped)
			return wrapped, nil
		})

	started := time.Now()
	claim, runErr := r.ExecuteCompleteProtocol(&ProviderRequestData{
		Name: "http",
		Params: &providers.HTTPProviderParams{
			URL: "https://example.com/", Method: "GET",
			ResponseMatches: []providers.ResponseMatch{{Type: "contains", Value: "iana.org"}},
		},
		SecretParams: &providers.HTTPProviderSecretParams{Headers: map[string]string{"accept": "application/json, text/plain, */*"}},
		Context:      `{"test":"incremental-demo"}`,
	})
	elapsed := time.Since(started)
	conn := target.Load()
	if conn == nil {
		t.Fatalf("target was not connected: %v", runErr)
	}
	selected := r.Client.SelectedResponseMode()
	wantMode := teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1
	if mode == "legacy" || minitls.IsTLS12CBCCipherSuite(r.Client.cipherSuite) {
		wantMode = teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF
	}
	if selected != wantMode {
		t.Fatalf("selected response mode %v, want %v", selected, wantMode)
	}
	if expectTimeout {
		if runErr == nil || !strings.Contains(runErr.Error(), "core TEE protocol timed out") {
			t.Fatalf("legacy transport without EOF: got %v, want core timeout", runErr)
		}
		if !conn.sawEOF.Load() {
			t.Fatal("origin EOF was never observed; fixture did not exercise withheld EOF")
		}
		t.Logf("case=%s selected=%v tls=%s cipher=0x%04x elapsed=%s expected_timeout=true", responseCase, selected, tlsVersion, r.Client.cipherSuite, elapsed)
		return
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	if claim == nil || claim.Claim == nil || claim.Claim.Identifier == "" {
		t.Fatal("attestor returned no claim identifier")
	}
	if claim.Signature == nil || claim.Signature.AttestorAddress == "" || len(claim.Signature.ClaimSignature) == 0 {
		t.Fatal("attestor returned no signed claim")
	}
	transcripts, err := r.GetTranscripts()
	if err != nil || !transcripts.BothReceived || !transcripts.BothSignaturesValid {
		t.Fatalf("transcript signatures not both valid: %+v, %v", transcripts, err)
	}
	response, err := r.GetResponseResults()
	if err != nil || !response.DecryptionSuccessful || response.DecryptedDataSize == 0 {
		t.Fatalf("HTTP response was not decrypted: %+v, %v", response, err)
	}
	if delay > 0 && time.Duration(conn.delayWaitNanos.Load()) < delay {
		t.Fatalf("fixture delay %s was shorter than %s", time.Duration(conn.delayWaitNanos.Load()), delay)
	}
	if holdEOF && conn.returnedEOF.Load() {
		t.Fatal("fixture returned EOF despite holdEOF")
	}
	t.Logf("case=%s selected=%v tls=%s cipher=0x%04x elapsed=%s delay=%s returned_eof=%v claim=%s response_bytes=%d both_signatures_valid=true",
		responseCase, selected, tlsVersion, r.Client.cipherSuite, elapsed,
		time.Duration(conn.delayWaitNanos.Load()), conn.returnedEOF.Load(), claim.Claim.Identifier, response.DecryptedDataSize)
}

func requireDemoLoopbackURL(rawURL, scheme string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != scheme || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return fmt.Errorf("demo requires a local %s endpoint: %q", scheme, rawURL)
	}
	return nil
}

// demoResponseConn delays delivery only after the HTTP request has been sent.
// It retains data returned alongside read errors and honors each read deadline.
// EOF can remain hidden until Close, modeling a transport that stays open.
type demoResponseConn struct {
	net.Conn
	requestSent func() bool
	delay       time.Duration
	holdEOF     bool
	closed      chan struct{}
	closeOnce   sync.Once
	deadlineMu  sync.Mutex
	deadline    time.Time

	// The capture reader alone owns pending data and delay state.
	pending       []byte
	pendingErr    error
	delayStarted  time.Time
	delayFinished bool
	readEOF       bool

	delayWaitNanos atomic.Int64
	sawEOF         atomic.Bool
	returnedEOF    atomic.Bool
}

func (c *demoResponseConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.deadline = deadline
	c.deadlineMu.Unlock()
	return c.Conn.SetReadDeadline(deadline)
}

func (c *demoResponseConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *demoResponseConn) wait(until time.Time) error {
	c.deadlineMu.Lock()
	deadline := c.deadline
	c.deadlineMu.Unlock()
	timedOut := until.IsZero() || (!deadline.IsZero() && deadline.Before(until))
	if timedOut {
		until = deadline
	}
	if until.IsZero() {
		<-c.closed
		return net.ErrClosed
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-c.closed:
		return net.ErrClosed
	case <-timer.C:
		if timedOut {
			return os.ErrDeadlineExceeded
		}
		return nil
	}
}

func (c *demoResponseConn) Read(p []byte) (int, error) {
	if len(c.pending) == 0 && c.pendingErr == nil && !c.readEOF {
		n, err := c.Conn.Read(p)
		c.pending = append(c.pending[:0], p[:n]...)
		c.pendingErr = err
		if errors.Is(err, io.EOF) {
			c.sawEOF.Store(true)
			if c.holdEOF {
				c.readEOF, c.pendingErr = true, nil
			}
		}
	}
	if !c.delayFinished && c.delay > 0 && c.requestSent() {
		if c.delayStarted.IsZero() {
			c.delayStarted = time.Now()
		}
		err := c.wait(c.delayStarted.Add(c.delay))
		c.delayWaitNanos.Store(int64(time.Since(c.delayStarted)))
		if err != nil {
			return 0, err
		}
		c.delayFinished = true
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	if len(c.pending) > 0 {
		return n, nil
	}
	err := c.pendingErr
	c.pendingErr = nil
	if errors.Is(err, io.EOF) {
		c.returnedEOF.Store(true)
	}
	if n == 0 && err == nil && c.readEOF {
		return 0, c.wait(time.Time{})
	}
	return n, err
}

func TestDemoResponseConnPreservesDelayedBytesAndEOF(t *testing.T) {
	payload := []byte("authenticated response bytes")
	base := &responseScriptConn{steps: []responseRead{{data: payload, err: io.EOF}}}
	conn := &demoResponseConn{
		Conn: base, requestSent: func() bool { return true },
		delay: 40 * time.Millisecond, closed: make(chan struct{}),
	}
	t.Cleanup(func() { _ = conn.Close() })
	buf := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(buf); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("delayed read = %d, %v", n, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf[:3])
	if n != 3 || err != nil || !bytes.Equal(buf[:n], payload[:3]) {
		t.Fatalf("first released bytes = %q, %v", buf[:n], err)
	}
	n, err = conn.Read(buf)
	if !bytes.Equal(buf[:n], payload[3:]) || !errors.Is(err, io.EOF) {
		t.Fatalf("remaining bytes = %q, %v", buf[:n], err)
	}
	if time.Duration(conn.delayWaitNanos.Load()) < conn.delay || !conn.returnedEOF.Load() {
		t.Fatal("delay or EOF evidence was not recorded")
	}
}

func TestDemoResponseConnWithheldEOFHonorsDeadlineAndClose(t *testing.T) {
	conn := &demoResponseConn{
		Conn: &responseScriptConn{}, requestSent: func() bool { return false },
		holdEOF: true, closed: make(chan struct{}),
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("withheld EOF = %d, %v", n, err)
	}
	if !conn.sawEOF.Load() || conn.returnedEOF.Load() {
		t.Fatal("fixture did not withhold EOF")
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed read = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the held EOF")
	}
}
