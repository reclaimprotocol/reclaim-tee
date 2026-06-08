package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type registerRequest struct {
	PairID         string `json:"pair_id"`
	Role           string `json:"role"`
	SelfAddr       string `json:"self_addr"`
	PeerAddrClaim  string `json:"peer_addr_claim"`
	ImageDigest    string `json:"image_digest"`
	AttestationJWT string `json:"attestation_jwt"`
}

type registerResponse struct {
	PairID string       `json:"pair_id"`
	Status store.Status `json:"status"`
}

// HandleRegister implements the three-signal /register endpoint per the
// multi-pair architecture plan: SA identity token + Confidential Space
// attestation + source-IP cross-consistency. Any single failure rejects.
//
// In standalone mode (ROUTER_STANDALONE=true) all three signals are
// skipped — the local dev demo can't produce real SA tokens or
// attestations. The claimed image_digest from the body is trusted as-is.
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := s.Logger

	var saEmail string
	if !s.Config.Standalone {
		saClaims, err := s.authenticateSA(r)
		if err != nil {
			log.Warn("register: SA token invalid", zap.Error(err))
			writeErr(w, http.StatusUnauthorized, "invalid SA token")
			return
		}
		saEmail = saClaims.Email
	}

	var req registerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	digest := req.ImageDigest
	if !s.Config.Standalone {
		validated, err := s.AttestValidator.Validate([]byte(req.AttestationJWT))
		if err != nil {
			log.Warn("register: attestation invalid",
				zap.String("pair_id", req.PairID), zap.Error(err))
			writeErr(w, http.StatusUnauthorized, "invalid attestation")
			return
		}
		if validated != req.ImageDigest {
			writeErr(w, http.StatusBadRequest,
				"image_digest body does not match attestation claim")
			return
		}
		if !s.Allowlist.Contains(validated) {
			writeErr(w, http.StatusForbidden, "image digest not in allowlist")
			return
		}
		digest = validated

		if !sourceIPMatches(r, req.SelfAddr) {
			log.Warn("register: source IP mismatch",
				zap.String("remote", r.RemoteAddr),
				zap.String("x_forwarded_for", r.Header.Get("X-Forwarded-For")),
				zap.String("self_addr", req.SelfAddr),
				zap.String("pair_id", req.PairID))
			writeErr(w, http.StatusForbidden, "source IP does not match self_addr")
			return
		}
	}

	// Lookup or create pair record, populate this role, enforce cross-consistency
	// against any already-registered peer side.
	p, err := s.Store.GetPair(ctx, req.PairID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		p = &store.Pair{
			ID:           req.PairID,
			RegisteredAt: time.Now(),
		}
	case err != nil:
		log.Error("register: store get failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	now := time.Now()
	// On first registration of a side, the side has not yet reported healthy
	// observations — seed the "unhealthy since" timestamps so threshold-based
	// degradation has a starting point.
	switch store.Role(req.Role) {
	case store.RoleK:
		if p.TEETAddr != "" && p.TEETAddr != req.PeerAddrClaim {
			writeErr(w, http.StatusBadRequest,
				"peer_addr_claim does not match already-registered TEE_T address")
			return
		}
		p.TEEKAddr = req.SelfAddr
		p.TEEKImageDigest = digest
		p.LastHeartbeatK = now
		p.ControlUnhealthySinceK = now
		p.OTUnreadySinceK = now
	case store.RoleT:
		if p.TEEKAddr != "" && p.TEEKAddr != req.PeerAddrClaim {
			writeErr(w, http.StatusBadRequest,
				"peer_addr_claim does not match already-registered TEE_K address")
			return
		}
		p.TEETAddr = req.SelfAddr
		p.TEETImageDigest = digest
		p.LastHeartbeatT = now
		p.ControlUnhealthySinceT = now
		p.OTUnreadySinceT = now
	}

	if err := s.Store.UpsertPair(ctx, p); err != nil {
		log.Error("register: store upsert failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	log.Info("register: pair member registered",
		zap.String("pair_id", req.PairID),
		zap.String("role", req.Role),
		zap.String("sa_email", saEmail),
		zap.String("image_digest", digest))

	writeJSON(w, http.StatusOK, registerResponse{
		PairID: p.ID,
		Status: p.EffectiveStatus(now, s.Config.HeartbeatStaleness,
			s.Config.ControlUnhealthy, s.Config.OTNotReady),
	})
}

func (req registerRequest) validate() error {
	// AttestationJWT is intentionally NOT required here — the handler
	// checks it (via AttestValidator) in production mode and skips it
	// entirely in standalone mode. Validation at this layer is purely
	// structural.
	switch {
	case req.PairID == "":
		return errors.New("pair_id is required")
	case req.Role != string(store.RoleK) && req.Role != string(store.RoleT):
		return errors.New("role must be K or T")
	case req.SelfAddr == "":
		return errors.New("self_addr is required")
	case req.PeerAddrClaim == "":
		return errors.New("peer_addr_claim is required")
	case req.ImageDigest == "":
		return errors.New("image_digest is required")
	}
	if _, err := uuid.Parse(req.PairID); err != nil {
		return errors.New("pair_id must be a valid UUID")
	}
	if _, _, err := net.SplitHostPort(req.SelfAddr); err != nil {
		return errors.New("self_addr must be host:port")
	}
	if _, _, err := net.SplitHostPort(req.PeerAddrClaim); err != nil {
		return errors.New("peer_addr_claim must be host:port")
	}
	return nil
}

// sourceIPMatches returns true if the request's source IP matches the
// host portion of self_addr. When the router runs behind Cloud Run /
// GFE, r.RemoteAddr is the load balancer's IP — useless for this
// check; X-Forwarded-For carries the actual client IP (leftmost entry,
// per Cloud Run conventions). Both inputs are tolerated in bare-host
// form for tests where RemoteAddr may not include a port.
func sourceIPMatches(r *http.Request, selfAddr string) bool {
	src := requestSourceIP(r)
	claimed, _, err := net.SplitHostPort(selfAddr)
	if err != nil {
		claimed = selfAddr
	}
	return src == claimed
}

// requestSourceIP returns the most-trustworthy client IP this router can
// see: the leftmost X-Forwarded-For entry when present (set by GFE /
// Cloud Run), otherwise r.RemoteAddr's host portion. The leftmost XFF
// entry is the original client; subsequent entries are intermediate
// proxies appended by each hop.
func requestSourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// "client, proxy1, proxy2" — first entry is the original client.
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
