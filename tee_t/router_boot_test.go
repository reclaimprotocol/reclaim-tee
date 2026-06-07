package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

// sendPairAssignmentTest is the test-side encoder mirroring TEE_K's
// sendPairAssignment — wraps pair_id in an Envelope and writes it as a
// binary WS frame. Kept here rather than imported from tee_k to avoid
// cross-package test dependencies.
func sendPairAssignmentTest(t *testing.T, conn *websocket.Conn, pairID string) {
	t.Helper()
	env := &teeproto.Envelope{
		Sender:      teeproto.Sender_SENDER_TEE_K,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeekPairAssignment{
			TeekPairAssignment: &teeproto.TEEKPairAssignment{PairId: pairID},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

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

func TestPortFromAddr(t *testing.T) {
	got, err := portFromAddr("10.0.0.2:443")
	if err != nil || got != "443" {
		t.Fatalf("portFromAddr(10.0.0.2:443) = %q, %v", got, err)
	}
	if _, err := portFromAddr("not-an-addr"); err == nil {
		t.Fatal("expected error on malformed address")
	}
}

// acceptAnyPeer is the test peer-cert verifier — returns nil regardless.
// The mTLS layer would normally use shared.VerifyRATLSPeer, but tests
// don't have real attestations to validate.
func acceptAnyPeer(_ [][]byte, _ [][]*x509.Certificate) error { return nil }

// peerListenerHarness wires up runPeerListener against an in-memory listener
// at a free 127.0.0.1 port and returns the address callers should dial.
type peerListenerHarness struct {
	addr       string
	state      *teetRouterState
	registers  *int32 // pointer so callers can read after the listener has updated
	heartbeats *int32
}

func startPeerListener(t *testing.T, ctx context.Context) *peerListenerHarness {
	t.Helper()

	// Bind directly — no find-then-reopen race.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()

	ratls, err := shared.NewRATLSManager(t.Context(), "tee_t", nil)
	if err != nil {
		t.Fatalf("ratls: %v", err)
	}
	tlsConfig := ratls.ServerTLSConfig()
	tlsConfig.ClientAuth = tls.RequireAnyClientCert
	tlsConfig.VerifyPeerCertificate = acceptAnyPeer

	state := &teetRouterState{}
	var registers, heartbeats int32
	register := func(_ context.Context, _ string) error {
		atomic.AddInt32(&registers, 1)
		return nil
	}
	startHeartbeat := func() { atomic.AddInt32(&heartbeats, 1) }

	go runPeerListener(ctx, listener, tlsConfig, state, register, startHeartbeat, shared.GetTEETLogger())

	return &peerListenerHarness{addr: addr, state: state, registers: &registers, heartbeats: &heartbeats}
}

// dialPeer is the test-side WebSocket dialer mimicking TEE_K. It returns
// a connected conn or fatals.
func dialPeer(t *testing.T, addr string) *websocket.Conn {
	t.Helper()
	ratls, err := shared.NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("client ratls: %v", err)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: acceptAnyPeer,
		GetClientCertificate:  ratls.GetClientCertificate,
		MinVersion:            tls.VersionTLS12,
	}
	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 5 * time.Second,
	}
	conn, _, err := dialer.Dial("wss://"+addr+"/ws/peer", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func TestPeerListener_PairIDHandshakeRegistersAndStartsHeartbeat(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	h := startPeerListener(t, ctx)

	conn := dialPeer(t, h.addr)
	defer conn.Close()

	const pairID = "00000000-0000-0000-0000-000000000001"
	sendPairAssignmentTest(t, conn, pairID)

	// Wait for the listener to process the handshake.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(h.registers) == 1 &&
			atomic.LoadInt32(h.heartbeats) == 1 &&
			h.state.controlHealthy.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(h.registers); got != 1 {
		t.Fatalf("register call count: got %d, want 1", got)
	}
	if got := atomic.LoadInt32(h.heartbeats); got != 1 {
		t.Fatalf("startHeartbeat call count: got %d, want 1", got)
	}
	if !h.state.controlHealthy.Load() {
		t.Fatal("controlHealthy not set after handshake")
	}
	if pid := h.state.pairID.Load(); pid == nil || *pid != pairID {
		t.Fatalf("pairID not stored correctly: got %v", pid)
	}
}

func TestPeerListener_InvalidPairIDIsRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	h := startPeerListener(t, ctx)
	conn := dialPeer(t, h.addr)
	defer conn.Close()

	sendPairAssignmentTest(t, conn, "not-a-uuid")

	// Give the listener time to read and reject.
	time.Sleep(100 * time.Millisecond)

	if got := atomic.LoadInt32(h.registers); got != 0 {
		t.Fatalf("register must not be called on invalid pair_id, got %d calls", got)
	}
	if h.state.controlHealthy.Load() {
		t.Fatal("controlHealthy must not be set on rejected handshake")
	}
}

func TestPeerListener_ReconnectWithSamePairIDDoesNotReRegister(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	h := startPeerListener(t, ctx)
	const pairID = "00000000-0000-0000-0000-000000000002"

	// First connection
	c1 := dialPeer(t, h.addr)
	sendPairAssignmentTest(t, c1, pairID)
	waitFor(t, func() bool { return atomic.LoadInt32(h.registers) == 1 }, "first register")
	_ = c1.Close()

	// Wait for listener to notice disconnect.
	waitFor(t, func() bool { return !h.state.controlHealthy.Load() }, "controlHealthy false after disconnect")

	// Reconnect with the SAME pair_id — register must not fire again.
	c2 := dialPeer(t, h.addr)
	sendPairAssignmentTest(t, c2, pairID)
	waitFor(t, func() bool { return h.state.controlHealthy.Load() }, "controlHealthy true after reconnect")

	if got := atomic.LoadInt32(h.registers); got != 1 {
		t.Fatalf("register count after reconnect: got %d, want 1", got)
	}
	_ = c2.Close()
}

func TestPeerListener_NewPairIDTriggersReRegister(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	h := startPeerListener(t, ctx)

	c1 := dialPeer(t, h.addr)
	sendPairAssignmentTest(t, c1, "00000000-0000-0000-0000-000000000003")
	waitFor(t, func() bool { return atomic.LoadInt32(h.registers) == 1 }, "first register")
	_ = c1.Close()
	waitFor(t, func() bool { return !h.state.controlHealthy.Load() }, "disconnect")

	c2 := dialPeer(t, h.addr)
	sendPairAssignmentTest(t, c2, "00000000-0000-0000-0000-000000000004")
	waitFor(t, func() bool { return atomic.LoadInt32(h.registers) == 2 }, "second register")

	if got := atomic.LoadInt32(h.heartbeats); got != 1 {
		t.Fatalf("startHeartbeat must still only fire once across pair_id changes, got %d", got)
	}
	_ = c2.Close()
}

// TestPairAssignment_ProtoRoundTrip is a sanity check on the wire format
// so a future renumbering of the oneof field would break this test rather
// than break silently in production.
func TestPairAssignment_ProtoRoundTrip(t *testing.T) {
	original := &teeproto.Envelope{
		Sender: teeproto.Sender_SENDER_TEE_K,
		Payload: &teeproto.Envelope_TeekPairAssignment{
			TeekPairAssignment: &teeproto.TEEKPairAssignment{PairId: "abc-123"},
		},
	}
	raw, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back teeproto.Envelope
	if err := proto.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pa, ok := back.Payload.(*teeproto.Envelope_TeekPairAssignment)
	if !ok {
		t.Fatalf("payload type: %T", back.Payload)
	}
	if pa.TeekPairAssignment.GetPairId() != "abc-123" {
		t.Fatalf("pair_id round trip: %q", pa.TeekPairAssignment.GetPairId())
	}
}

// waitFor polls predicate until true or timeout fires.
func waitFor(t *testing.T, pred func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

