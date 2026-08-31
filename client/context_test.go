package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/providers"
)

func TestNewReclaimClientFromJSONWithContextCancelsAllocation(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(releaseHandler) })

	providerJSON, err := json.Marshal(&ProviderRequestData{
		Name: "http",
		Params: &providers.HTTPProviderParams{
			URL:             "https://example.com/",
			Method:          http.MethodGet,
			ResponseMatches: []providers.ResponseMatch{{Value: "ok", Type: "contains"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	type result struct {
		client *ReclaimClient
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		client, err := NewReclaimClientFromJSONWithContext(ctx, string(providerJSON), `{"routerUrl":"`+server.URL+`"}`)
		resultCh <- result{client: client, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("allocation request did not start")
	}
	startedAt := time.Now()
	cancel()

	select {
	case result := <-resultCh:
		if result.client != nil {
			t.Fatal("constructor returned a client after cancellation")
		}
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("constructor error = %v, want context canceled", result.err)
		}
		if elapsed := time.Since(startedAt); elapsed >= 250*time.Millisecond {
			t.Fatalf("constructor cancellation took %s, want less than 250ms", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("constructor did not return after cancellation")
	}
}
