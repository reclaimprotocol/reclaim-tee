package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type fakeSAValidator struct {
	claims *auth.SAClaims
	err    error
}

func (f *fakeSAValidator) Validate(_ context.Context, _ string) (*auth.SAClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

type fakeAttestValidator struct {
	digest string
	err    error
}

func (f *fakeAttestValidator) Validate(_ []byte) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.digest, nil
}

const (
	approvedDigest = "sha256:abc123"
	teekIP         = "10.0.0.1"
	teetIP         = "10.0.0.2"
	pairID         = "00000000-0000-0000-0000-000000000001"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		Store: store.NewMemoryStore(),
		SAValidator: &fakeSAValidator{
			claims: &auth.SAClaims{
				Email:            "tee-vm-1@new-reclaim-architecture.iam.gserviceaccount.com",
				RegisteredClaims: jwt.RegisteredClaims{},
			},
		},
		AttestValidator: &fakeAttestValidator{digest: approvedDigest},
		Allowlist:       auth.NewAllowlist([]string{approvedDigest}),
		Logger:          zap.NewNop(),
		Config: &config.Config{
			HeartbeatStaleness: 15 * time.Second,
			// Thresholds are zero so handler tests see "control/ot bad now → status
			// flips this turn." Sustained-threshold semantics are unit-tested
			// directly on the Pair model in store/types_test.go.
			ControlUnhealthy: 0,
			OTNotReady:       0,
			JWTExpiry:        60 * time.Second,
			JWTIssuer:        "router.test",
		},
	}
}

func doRegister(t *testing.T, s *Server, body registerRequest, remoteAddr, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(raw))
	req.RemoteAddr = remoteAddr
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	s.HandleRegister(w, req)
	return w
}

func validBody(role, selfAddr, peerAddr string) registerRequest {
	return registerRequest{
		PairID:         pairID,
		Role:           role,
		SelfAddr:       selfAddr,
		PeerAddrClaim:  peerAddr,
		ImageDigest:    approvedDigest,
		AttestationJWT: "fake-attestation-jwt",
	}
}

func TestRegisterHappyPathK(t *testing.T) {
	s := newTestServer(t)
	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer fake-sa-token")

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, body=%s", w.Code, w.Body.String())
	}
	p, err := s.Store.GetPair(t.Context(), pairID)
	if err != nil {
		t.Fatalf("pair not stored: %v", err)
	}
	if p.TEEKAddr != teekIP+":443" || p.TEEKImageDigest != approvedDigest {
		t.Fatalf("K not populated: %+v", p)
	}
	if p.TEETAddr != "" {
		t.Fatalf("T should be empty: %q", p.TEETAddr)
	}
	if got := p.EffectiveStatus(time.Now(), 15*time.Second, 30*time.Second, 60*time.Second); got != store.StatusRegistering {
		t.Fatalf("status: %v", got)
	}
}

func TestRegisterBothSidesCrossConsistency(t *testing.T) {
	s := newTestServer(t)

	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("K status: got %d body=%s", w.Code, w.Body.String())
	}

	w = doRegister(t, s,
		validBody("T", teetIP+":443", teekIP+":443"),
		teetIP+":54321", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("T status: got %d body=%s", w.Code, w.Body.String())
	}

	p, err := s.Store.GetPair(t.Context(), pairID)
	if err != nil {
		t.Fatalf("get pair: %v", err)
	}
	if p.TEEKAddr == "" || p.TEETAddr == "" {
		t.Fatalf("both sides should be set: %+v", p)
	}
}

func TestRegisterRejectsPeerAddrMismatch(t *testing.T) {
	s := newTestServer(t)

	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		teekIP+":12345", "Bearer fake-sa-token")
	if w.Code != http.StatusOK {
		t.Fatalf("K status: %d", w.Code)
	}

	// T claims a different K address than the one that registered first.
	body := validBody("T", teetIP+":443", "10.0.0.99:443")
	w = doRegister(t, s, body, teetIP+":54321", "Bearer fake-sa-token")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on peer mismatch, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRegisterRejectsMissingAuth(t *testing.T) {
	s := newTestServer(t)
	w := doRegister(t, s, validBody("K", teekIP+":443", teetIP+":443"), teekIP+":12345", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRegisterRejectsBadSAToken(t *testing.T) {
	s := newTestServer(t)
	s.SAValidator = &fakeSAValidator{err: errors.New("bad token")}
	w := doRegister(t, s, validBody("K", teekIP+":443", teetIP+":443"), teekIP+":12345", "Bearer x")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRegisterRejectsBadAttestation(t *testing.T) {
	s := newTestServer(t)
	s.AttestValidator = &fakeAttestValidator{err: errors.New("bad attest")}
	w := doRegister(t, s, validBody("K", teekIP+":443", teetIP+":443"), teekIP+":12345", "Bearer x")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRegisterRejectsDigestMismatch(t *testing.T) {
	s := newTestServer(t)
	body := validBody("K", teekIP+":443", teetIP+":443")
	body.ImageDigest = "sha256:claimed-different"
	w := doRegister(t, s, body, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRegisterRejectsDigestNotInAllowlist(t *testing.T) {
	s := newTestServer(t)
	s.AttestValidator = &fakeAttestValidator{digest: "sha256:not-approved"}
	body := validBody("K", teekIP+":443", teetIP+":443")
	body.ImageDigest = "sha256:not-approved"
	w := doRegister(t, s, body, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRegisterRejectsSourceIPMismatch(t *testing.T) {
	s := newTestServer(t)
	// Body claims self_addr=10.0.0.1 but request comes from 10.0.0.99
	w := doRegister(t, s,
		validBody("K", teekIP+":443", teetIP+":443"),
		"10.0.0.99:12345", "Bearer x")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRegisterRejectsBadRole(t *testing.T) {
	s := newTestServer(t)
	body := validBody("X", teekIP+":443", teetIP+":443")
	w := doRegister(t, s, body, teekIP+":12345", "Bearer x")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}
