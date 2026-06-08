package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"go.uber.org/zap"
)

type allowlistView struct {
	Digests []string `json:"digests"`
}

type addDigestRequest struct {
	Digest string `json:"digest"`
}

// HandleListAllowlist returns the current cached allowlist. Admin auth.
func (s *Server) HandleListAllowlist(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	digests := s.Allowlist.List()
	slices.Sort(digests)
	writeJSON(w, http.StatusOK, allowlistView{Digests: digests})
}

// HandleAddDigest adds a digest to the allowlist (persists to store +
// updates cache). Admin auth. Idempotent — adding an already-present
// digest returns 200.
func (s *Server) HandleAddDigest(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	var req addDigestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if err := validateDigestFormat(req.Digest); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Allowlist.Add(r.Context(), req.Digest); err != nil {
		s.Logger.Error("allowlist add failed", zap.String("digest", req.Digest), zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.Logger.Info("allowlist: digest added", zap.String("digest", req.Digest))
	writeJSON(w, http.StatusOK, map[string]string{"digest": req.Digest})
}

// HandleRemoveDigest removes a digest from the allowlist. Admin auth.
// The path is /allowlist/{digest}; the digest is URL-decoded from the
// path value. Idempotent — removing a missing digest returns 204.
func (s *Server) HandleRemoveDigest(w http.ResponseWriter, r *http.Request) {
	if err := s.adminAuthOrDeny(w, r); err != nil {
		return
	}
	raw := r.PathValue("digest")
	digest, err := url.PathUnescape(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	if err := validateDigestFormat(digest); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Allowlist.Remove(r.Context(), digest); err != nil {
		s.Logger.Error("allowlist remove failed", zap.String("digest", digest), zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "store error")
		return
	}
	s.Logger.Info("allowlist: digest removed", zap.String("digest", digest))
	w.WriteHeader(http.StatusNoContent)
}

// validateDigestFormat enforces the sha256:<64-hex-char> shape so a
// typo can't pollute the allowlist with junk that no real attestation
// would ever match anyway. Cheap, catches operator mistakes early.
func validateDigestFormat(d string) error {
	rest, ok := strings.CutPrefix(d, "sha256:")
	if !ok {
		return errBadDigestPrefix
	}
	if len(rest) != 64 {
		return errBadDigestLength
	}
	for _, c := range rest {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return errBadDigestHex
		}
	}
	return nil
}

var (
	errBadDigestPrefix = &simpleErr{"digest must start with sha256:"}
	errBadDigestLength = &simpleErr{"digest hex portion must be exactly 64 chars"}
	errBadDigestHex    = &simpleErr{"digest hex portion must be lowercase [0-9a-f]"}
)

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }
