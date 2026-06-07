//go:build !mobile

package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RouterClient talks to the multi-pair router service from inside a TEE.
// All requests carry a GCP service-account identity token in
// Authorization: Bearer. The token is fetched fresh per call via the
// supplied TokenSource (which in production hits the GCP metadata server).
type RouterClient struct {
	baseURL    string
	httpClient *http.Client
	tokens     TokenSource
}

// TokenSource returns a fresh GCP SA identity token for the given audience.
// In production: queries http://metadata.google.internal/.../identity?audience=.
// In tests: a stub.
type TokenSource func(ctx context.Context, audience string) (string, error)

// NewRouterClient builds a client pointing at the router base URL (e.g.
// "https://tee.reclaimprotocol.org"). The token source is invoked per
// authenticated request; pass MetadataServerTokenSource for production.
func NewRouterClient(baseURL string, tokens TokenSource) *RouterClient {
	return &RouterClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		tokens:     tokens,
	}
}

// RegisterRequest is the body of POST /register.
type RegisterRequest struct {
	PairID         string `json:"pair_id"`
	Role           string `json:"role"`
	SelfAddr       string `json:"self_addr"`
	PeerAddrClaim  string `json:"peer_addr_claim"`
	ImageDigest    string `json:"image_digest"`
	AttestationJWT string `json:"attestation_jwt"`
}

// RegisterResponse is the body returned by /register.
type RegisterResponse struct {
	PairID string `json:"pair_id"`
	Status string `json:"status"`
}

// Register calls POST /register. The router's audience for SA-token
// validation is configured server-side; we pass the same value when we
// fetch our identity token so the token's aud claim matches.
func (c *RouterClient) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.postJSON(ctx, "/register", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// HeartbeatRequest is the body of POST /heartbeat.
type HeartbeatRequest struct {
	PairID            string `json:"pair_id"`
	Role              string `json:"role"`
	ControlHealthy    bool   `json:"control_healthy"`
	OTReady           bool   `json:"ot_ready"`
	ActiveSessions    int    `json:"active_sessions"`
	LastPeerContactMS int64  `json:"last_peer_contact_ms"`
}

// HeartbeatResponse is the body returned by /heartbeat.
type HeartbeatResponse struct {
	PairID string `json:"pair_id"`
	Status string `json:"status"`
}

// Heartbeat calls POST /heartbeat. A 404 indicates the router has no record
// of this pair_id — the TEE should treat this as evidence that it needs to
// re-register (e.g. after a router restart in single-instance mode).
func (c *RouterClient) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.postJSON(ctx, "/heartbeat", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ErrRouterNotFound is returned when the router replies 404 — most commonly
// from /heartbeat for an unknown pair_id. Callers can match this with
// errors.Is(err, shared.ErrRouterNotFound) and trigger a re-register.
var ErrRouterNotFound = errors.New("router: not found")

func (c *RouterClient) postJSON(ctx context.Context, path string, reqBody, respBody any) error {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	token, err := c.tokens(ctx, c.baseURL)
	if err != nil {
		return fmt.Errorf("get SA identity token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusNotFound {
		return ErrRouterNotFound
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("router %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	if respBody == nil {
		return nil
	}
	if err := json.Unmarshal(body, respBody); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// MetadataServerTokenSource is the production TokenSource: it asks the GCP
// instance metadata server for an SA identity token scoped to the given
// audience. Works only on GCE VMs (incl. Confidential Space).
func MetadataServerTokenSource(ctx context.Context, audience string) (string, error) {
	const mdHost = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
	u := mdHost + "?audience=" + url.QueryEscape(audience) + "&format=full"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %d: %s", resp.StatusCode, string(body))
	}
	return string(bytes.TrimSpace(body)), nil
}
