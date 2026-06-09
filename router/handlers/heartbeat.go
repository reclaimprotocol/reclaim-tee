package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/router/store"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type heartbeatRequest struct {
	PairID         string `json:"pair_id"`
	Role           string `json:"role"`
	ControlHealthy bool   `json:"control_healthy"`
	OTReady        bool   `json:"ot_ready"`
	ActiveSessions int    `json:"active_sessions"`
	// LastPeerContactMS is informational only — logged at debug for ops
	// diagnostics but not used in status derivation.
	LastPeerContactMS int64 `json:"last_peer_contact_ms"`
}

type heartbeatResponse struct {
	PairID string       `json:"pair_id"`
	Status store.Status `json:"status"`
}

// HandleHeartbeat updates a pair's liveness + health observations from one
// side. Identity rests on the SA identity token; attestation is not
// re-checked here — the initial /register carries it forward. A source-IP
// cross-check used to live here but was dropped along with the equivalent
// check in /register (XFF leftmost is attacker-controlled behind GCP LB).
func (s *Server) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := s.Logger

	var saEmail string
	if !s.Config.Standalone {
		saClaims, err := s.authenticateSA(r)
		if err != nil {
			log.Warn("heartbeat: SA token invalid", zap.Error(err))
			writeErr(w, http.StatusUnauthorized, "invalid SA token")
			return
		}
		saEmail = saClaims.Email
	}

	var req heartbeatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := req.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	p, err := s.Store.GetPair(ctx, req.PairID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "pair not found")
		return
	}

	registeredAddr := p.TEEKAddr
	expectedSAEmail := s.Config.TEEKSAEmail
	if store.Role(req.Role) == store.RoleT {
		registeredAddr = p.TEETAddr
		expectedSAEmail = s.Config.TEETSAEmail
	}
	if registeredAddr == "" {
		writeErr(w, http.StatusNotFound, "role has not registered for this pair")
		return
	}
	if !s.Config.Standalone && expectedSAEmail != "" && expectedSAEmail != saEmail {
		log.Warn("heartbeat: SA email not approved for role",
			zap.String("role", req.Role),
			zap.String("expected", expectedSAEmail),
			zap.String("got", saEmail))
		writeErr(w, http.StatusForbidden, "SA identity not approved for role")
		return
	}

	now := time.Now()
	prevStatus := p.EffectiveStatus(now,
		s.Config.HeartbeatStaleness, s.Config.ControlUnhealthy, s.Config.OTNotReady)

	switch store.Role(req.Role) {
	case store.RoleK:
		p.LastHeartbeatK = now
		applyControlObservation(&p.ControlHealthyK, &p.ControlUnhealthySinceK, req.ControlHealthy, now)
		applyOTObservation(&p.OTReadyK, &p.OTUnreadySinceK, req.OTReady, now)
	case store.RoleT:
		p.LastHeartbeatT = now
		applyControlObservation(&p.ControlHealthyT, &p.ControlUnhealthySinceT, req.ControlHealthy, now)
		applyOTObservation(&p.OTReadyT, &p.OTUnreadySinceT, req.OTReady, now)
	}
	p.ActiveSessions = req.ActiveSessions

	newStatus := p.EffectiveStatus(now,
		s.Config.HeartbeatStaleness, s.Config.ControlUnhealthy, s.Config.OTNotReady)
	if newStatus == store.StatusReady && p.ReadyAt.IsZero() {
		p.ReadyAt = now
	}

	if err := s.Store.UpsertPair(ctx, p); err != nil {
		log.Error("heartbeat: store upsert failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}

	if newStatus != prevStatus {
		log.Info("pair status changed",
			zap.String("pair_id", p.ID),
			zap.String("from", string(prevStatus)),
			zap.String("to", string(newStatus)))
	}
	log.Debug("heartbeat received",
		zap.String("pair_id", p.ID),
		zap.String("role", req.Role),
		zap.Bool("control_healthy", req.ControlHealthy),
		zap.Bool("ot_ready", req.OTReady),
		zap.Int("active_sessions", req.ActiveSessions),
		zap.Int64("last_peer_contact_ms", req.LastPeerContactMS))

	writeJSON(w, http.StatusOK, heartbeatResponse{
		PairID: p.ID,
		Status: newStatus,
	})
}

func (req heartbeatRequest) validate() error {
	switch {
	case req.PairID == "":
		return errors.New("pair_id is required")
	case req.Role != string(store.RoleK) && req.Role != string(store.RoleT):
		return errors.New("role must be K or T")
	}
	if _, err := uuid.Parse(req.PairID); err != nil {
		return errors.New("pair_id must be a valid UUID")
	}
	return nil
}

// applyControlObservation updates the most-recent control_healthy bool and
// the "unhealthy since" timestamp atomically: clear on transition to healthy,
// set on transition into unhealthy, leave alone while still unhealthy.
func applyControlObservation(healthy *bool, since *time.Time, observed bool, now time.Time) {
	*healthy = observed
	switch {
	case observed:
		*since = time.Time{}
	case since.IsZero():
		*since = now
	}
}

// applyOTObservation mirrors applyControlObservation for the ot_ready bit.
func applyOTObservation(ready *bool, since *time.Time, observed bool, now time.Time) {
	*ready = observed
	switch {
	case observed:
		*since = time.Time{}
	case since.IsZero():
		*since = now
	}
}
