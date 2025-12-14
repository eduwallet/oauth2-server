package cimd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

func TestIsCIMDClientID(t *testing.T) {
	cfg := &config.Config{}

	valid := "https://example.com/client.json"
	if !IsCIMDClientID(valid, cfg) {
		t.Fatalf("expected %s to be valid CIMD client id", valid)
	}

	invalid := "http://example.com/client.json"
	if IsCIMDClientID(invalid, cfg) {
		t.Fatalf("expected %s to be invalid when http is not permitted", invalid)
	}

	cfg.CIMD.HttpPermitted = true
	if !IsCIMDClientID(invalid, cfg) {
		t.Fatalf("expected %s to be valid when HTTP permitted", invalid)
	}
}

func TestAllowlistEnforcement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		location := scheme + "://" + r.Host
		w.Write([]byte(`{"client_id":"` + location + `"}`))
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.CIMD.AllowlistEnabled = true
	cfg.CIMD.Allowlist = []string{"example.com"} // not matching srv host

	mem := storage.NewMemoryStore()
	logger := logrus.New()
	msw := store.NewMemoryStoreWrapper(mem, logger)

	if _, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL); err == nil {
		t.Fatalf("expected error due to allowlist, but got none")
	}
}

func TestMetadataPolicyEnforcement(t *testing.T) {
	meta := `{"client_id":"http://localhost/cli","token_endpoint_auth_method":"none"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(meta))
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.CIMD.HttpPermitted = true
	cfg.CIMD.MetadataPolicyEnabled = true
	cfg.CIMD.MetadataPolicy = "required_fields:redirect_uris"

	mem := storage.NewMemoryStore()
	logger := logrus.New()
	msw := store.NewMemoryStoreWrapper(mem, logger)

	if _, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL); err == nil {
		t.Fatalf("expected metadata policy violation error, but got none")
	}
}

func TestCachingBehavior(t *testing.T) {
	// server that can change response; we will set response dynamically
	var current string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write([]byte(current))
	}))
	defer srv.Close()

	// initial metadata
	current = fmt.Sprintf(`{"client_id":"%s","redirect_uris":["%s/cb"]}`, srv.URL, srv.URL)

	cfg := &config.Config{}
	cfg.CIMD.HttpPermitted = true

	mem := storage.NewMemoryStore()
	logger := logrus.New()
	msw := store.NewMemoryStoreWrapper(mem, logger)

	c1, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL)
	if err != nil {
		t.Fatalf("initial register failed: %v", err)
	}

	// change server metadata
	current = fmt.Sprintf(`{"client_id":"%s","redirect_uris":["%s/other"]}`, srv.URL, srv.URL)

	c2, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL)
	if err != nil {
		t.Fatalf("second register failed: %v", err)
	}

	if c1.MetadataDocumentUpdatedAt != c2.MetadataDocumentUpdatedAt {
		t.Fatalf("expected cached metadata to be used (no update), but updatedAt changed")
	}
}

func TestRateLimiting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		location := scheme + "://" + r.Host
		w.Write([]byte(`{"client_id":"` + location + `"}`))
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.CIMD.HttpPermitted = true

	// fill fetch history to simulate hitting limit
	u, _ := url.Parse(srv.URL)
	host := u.Hostname()
	fetchHistoryMu.Lock()
	var stamps []time.Time
	for i := 0; i < defaultFetchLimit; i++ {
		stamps = append(stamps, time.Now())
	}
	fetchHistory[host] = stamps
	fetchHistoryMu.Unlock()

	mem := storage.NewMemoryStore()
	logger := logrus.New()
	msw := store.NewMemoryStoreWrapper(mem, logger)

	if _, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL); err == nil {
		t.Fatalf("expected rate limit error, but got none")
	}
}

func TestRateLimitingConfig(t *testing.T) {
	// Set small fetch limit via config and verify enforcement
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		location := scheme + "://" + r.Host
		w.Write([]byte(`{"client_id":"` + location + `"}`))
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.CIMD = &config.CIMDConfig{}
	cfg.CIMD.HttpPermitted = true
	cfg.CIMD.AlwaysRetrieved = true
	cfg.CIMD.FetchLimit = 2
	cfg.CIMD.FetchWindowSeconds = 60

	// Ensure history cleared for host
	u, _ := url.Parse(srv.URL)
	host := u.Hostname()
	fetchHistoryMu.Lock()
	delete(fetchHistory, host)
	fetchHistoryMu.Unlock()

	mem := storage.NewMemoryStore()
	logger := logrus.New()
	msw := store.NewMemoryStoreWrapper(mem, logger)

	// First fetch should succeed
	if _, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL); err != nil {
		t.Fatalf("expected first fetch to succeed, got: %v", err)
	}

	// Second fetch should also succeed (limit = 2)
	if _, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL); err != nil {
		t.Fatalf("expected second fetch to succeed, got: %v", err)
	}

	// Third fetch should be rate-limited
	if _, err := RegisterClientFromMetadata(context.Background(), cfg, msw, srv.URL); err == nil {
		t.Fatalf("expected third fetch to be rate-limited, but it succeeded")
	}
}
