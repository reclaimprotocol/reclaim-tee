package client

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AllocationResponse is what the router returns from POST /allocate.
// Mirrors router/handlers/allocate.go's allocateResponse — duplicated
// here so client/ doesn't import the router module.
type AllocationResponse struct {
	PairID   string `json:"pair_id"`
	TEEKAddr string `json:"teek_addr"`
	TEETAddr string `json:"teet_addr"`
	JWT      string `json:"jwt"`
}

// AllocatePair hits the router's /allocate endpoint with the supplied
// client nonce and returns the pair allocation + JWT. routerURL is the
// base URL (e.g. http://localhost:9090 or https://tee.reclaimprotocol.org).
func AllocatePair(routerURL, clientNonce string) (*AllocationResponse, error) {
	return AllocatePairWithContext(context.Background(), routerURL, clientNonce)
}

// AllocatePairWithContext hits the router's /allocate endpoint and cancels the
// request when ctx is done. The client's 10-second timeout remains the upper bound.
func AllocatePairWithContext(ctx context.Context, routerURL, clientNonce string) (*AllocationResponse, error) {
	// Announce the attestation types this client can verify so the router never
	// allocates a pair we can't check. Wire values mirror shared.AttestationType*
	// ("cs","sev-snp","secure-boot"); the client package cannot import shared.
	body, err := json.Marshal(struct {
		ClientNonce string   `json:"client_nonce"`
		Accepts     []string `json:"accepts"`
	}{
		ClientNonce: clientNonce,
		Accepts:     []string{"cs", "sev-snp", "secure-boot"},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, routerURL+"/allocate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST /allocate: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /allocate: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/allocate returned %d: %s", resp.StatusCode, respBody)
	}
	var out AllocationResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}
