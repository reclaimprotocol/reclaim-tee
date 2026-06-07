package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/router/auth"
	"github.com/reclaimprotocol/reclaim-tee/router/config"
	"github.com/reclaimprotocol/reclaim-tee/router/signer"
	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"go.uber.org/zap"
)

// Server bundles the dependencies the router HTTP handlers need.
type Server struct {
	Store           store.Store
	SAValidator     auth.SAValidator
	AttestValidator auth.AttestationValidator
	Allowlist       *auth.Allowlist
	Signer          signer.Signer
	Logger          *zap.Logger
	Config          *config.Config
}

// Routes returns the router's HTTP mux. New endpoints are wired here.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", Healthz)
	mux.HandleFunc("POST /register", s.HandleRegister)
	mux.HandleFunc("POST /heartbeat", s.HandleHeartbeat)
	mux.HandleFunc("POST /allocate", s.HandleAllocate)
	mux.HandleFunc("GET /pairs", s.HandleListPairs)
	mux.HandleFunc("POST /pairs/{id}/drain", s.HandleDrainPair)
	mux.HandleFunc("POST /pairs/{id}/dead", s.HandleKillPair)
	return mux
}

// authenticateSA validates the Authorization: Bearer SA-identity-token header
// on a request and returns its claims, or an HTTP-friendly error.
func (s *Server) authenticateSA(r *http.Request) (*auth.SAClaims, error) {
	authz := r.Header.Get("Authorization")
	saToken, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return nil, errors.New("missing or malformed Authorization header")
	}
	return s.SAValidator.Validate(r.Context(), saToken)
}

// errAdminDisabled is returned when an admin endpoint is hit but ADMIN_TOKEN
// is not configured. Callers map this to 503 (vs 401) so operators can tell
// "config is missing" apart from "I forgot the token."
var errAdminDisabled = errors.New("admin endpoints not configured")

// authenticateAdmin enforces the static admin bearer token. A blank
// AdminToken in config disables admin endpoints entirely.
func (s *Server) authenticateAdmin(r *http.Request) error {
	if s.Config.AdminToken == "" {
		return errAdminDisabled
	}
	authz := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return errors.New("missing or malformed Authorization header")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.Config.AdminToken)) != 1 {
		return errors.New("invalid admin token")
	}
	return nil
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
