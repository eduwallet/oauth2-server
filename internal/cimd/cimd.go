package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
)

var (
	fetchHistory   = make(map[string][]time.Time)
	fetchHistoryMu sync.Mutex
	// Default fetch limits when not configured: 60 requests per minute
	defaultFetchLimit  = 60
	defaultFetchWindow = time.Minute
)

// IsCIMDClientID returns true if the provided client_id looks like a CIMD URL
func IsCIMDClientID(id string, cfg *config.Config) bool {
	u, err := url.Parse(id)
	if err != nil {
		return false
	}
	// Scheme must be https unless HttpPermitted is true
	if u.Scheme != "https" && !(cfg.CIMD.HttpPermitted && u.Scheme == "http") {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	if u.User != nil || u.Fragment != "" {
		return false
	}
	if u.RawQuery != "" && !cfg.CIMD.QueryPermitted {
		return false
	}
	// no . or .. segments
	parts := strings.Split(u.Path, "/")
	for _, p := range parts {
		if p == "." || p == ".." {
			return false
		}
	}
	return true
}

// FetchMetadata fetches JSON metadata from the given location and returns a map
func FetchMetadata(ctx context.Context, location string) (map[string]interface{}, time.Time, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("failed to fetch metadata: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, time.Time{}, time.Time{}, err
	}

	// Determine expiry from Cache-Control or Expires header (simplified)
	var expires time.Time
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		// look for max-age
		if strings.Contains(cc, "max-age=") {
			parts := strings.Split(cc, "max-age=")
			if len(parts) > 1 {
				var s string
				s = parts[1]
				// strip possible trailing
				if i := strings.IndexAny(s, ", "); i != -1 {
					s = s[:i]
				}
				if sec, err := time.ParseDuration(s + "s"); err == nil {
					expires = time.Now().Add(sec)
				}
			}
		}
	}
	if expires.IsZero() {
		if ex := resp.Header.Get("Expires"); ex != "" {
			if t, err := http.ParseTime(ex); err == nil {
				expires = t
			}
		}
	}

	updatedAt := time.Now()
	if !expires.IsZero() {
		// cap at 1 day for safety
		max := time.Now().Add(24 * time.Hour)
		if expires.After(max) {
			expires = max
		}
	} else {
		// default to 1 day
		expires = time.Now().Add(24 * time.Hour)
	}

	return meta, expires, updatedAt, nil
}

// isHostAllowlisted checks if the host is allowed by allowlist when enabled
func isHostAllowlisted(u *url.URL, cfg *config.Config) bool {
	if !cfg.CIMD.AllowlistEnabled || len(cfg.CIMD.Allowlist) == 0 {
		return true
	}
	host := u.Hostname()
	for _, a := range cfg.CIMD.Allowlist {
		a = strings.TrimSpace(a)
		if a == "*" || a == host {
			return true
		}
		// support dot-prefix for suffix match (.example.com)
		if strings.HasPrefix(a, ".") && strings.HasSuffix(host, a) {
			return true
		}
		// support wildcard prefix *.example.com
		if strings.HasPrefix(a, "*.") && strings.HasSuffix(host, strings.TrimPrefix(a, "*.")) {
			return true
		}
	}
	return false
}

// enforceFetchRateLimit enforces a simple per-host rate limit
func enforceFetchRateLimit(u *url.URL, cfg *config.Config) error {
	host := u.Hostname()
	fetchHistoryMu.Lock()
	defer fetchHistoryMu.Unlock()

	now := time.Now()
	window := defaultFetchWindow
	limit := defaultFetchLimit
	// Use configured values if present
	if cfg != nil && cfg.CIMD != nil {
		if cfg.CIMD.FetchWindowSeconds > 0 {
			window = time.Duration(cfg.CIMD.FetchWindowSeconds) * time.Second
		}
		if cfg.CIMD.FetchLimit > 0 {
			limit = cfg.CIMD.FetchLimit
		}
	}

	// prune old
	times := fetchHistory[host]
	var pruned []time.Time
	for _, t := range times {
		if now.Sub(t) <= window {
			pruned = append(pruned, t)
		}
	}
	if len(pruned) >= limit {
		return fmt.Errorf("rate limit exceeded for host %s", host)
	}
	pruned = append(pruned, now)
	fetchHistory[host] = pruned
	return nil
}

// ValidateMetadataPolicy applies any configured metadata policy checks (very small policy language)
func ValidateMetadataPolicy(meta map[string]interface{}, cfg *config.Config) error {
	if cfg == nil || !cfg.CIMD.MetadataPolicyEnabled || strings.TrimSpace(cfg.CIMD.MetadataPolicy) == "" {
		return nil
	}
	// policy is semicolon separated list of key:value
	parts := strings.Split(cfg.CIMD.MetadataPolicy, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		vals := strings.Split(kv[1], ",")
		for i := range vals {
			vals[i] = strings.TrimSpace(vals[i])
		}

		switch key {
		case "required_fields":
			for _, f := range vals {
				if f == "" {
					continue
				}
				if _, ok := meta[f]; !ok {
					return fmt.Errorf("metadata policy violation: required field '%s' missing", f)
				}
			}
		case "forbidden_fields":
			for _, f := range vals {
				if f == "" {
					continue
				}
				if _, ok := meta[f]; ok {
					return fmt.Errorf("metadata policy violation: forbidden field '%s' present", f)
				}
			}
		case "required_grant_types":
			// check that grant_types contains each required
			arr, _ := meta["grant_types"].([]interface{})
			gm := make(map[string]bool)
			for _, v := range arr {
				if s, ok := v.(string); ok {
					gm[s] = true
				}
			}
			for _, req := range vals {
				if req == "" {
					continue
				}
				if !gm[req] {
					return fmt.Errorf("metadata policy violation: required grant type '%s' missing", req)
				}
			}
		}
	}
	return nil
}

// ValidateMetadata performs basic CIMD restrictions
func ValidateMetadata(meta map[string]interface{}, location string) error {
	cid, ok := meta["client_id"].(string)
	if !ok || cid == "" {
		return errors.New("metadata missing client_id")
	}
	if cid != location {
		return errors.New("metadata client_id does not match location")
	}
	if t, ok := meta["token_endpoint_auth_method"].(string); ok {
		// disallow symmetric secret methods
		if t == "client_secret_basic" || t == "client_secret_post" || t == "client_secret_jwt" {
			return errors.New("symmetric token endpoint auth methods are not allowed in CIMD metadata")
		}
	}
	// client_secret must not be present
	if _, ok := meta["client_secret"]; ok {
		return errors.New("client_secret MUST not be present in CIMD metadata")
	}
	return nil
}

// CreateClientFromMetadata builds a fosite client from metadata map
func CreateClientFromMetadata(meta map[string]interface{}, location string, expires time.Time, updatedAt time.Time) (*store.CustomClient, error) {
	cid, _ := meta["client_id"].(string)
	if cid == "" {
		return nil, errors.New("client_id missing")
	}

	dc := &fosite.DefaultClient{
		ID: cid,
	}

	if arr, ok := meta["redirect_uris"].([]interface{}); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				dc.RedirectURIs = append(dc.RedirectURIs, s)
			}
		}
	}
	if arr, ok := meta["grant_types"].([]interface{}); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				dc.GrantTypes = append(dc.GrantTypes, s)
			}
		}
	}
	if arr, ok := meta["response_types"].([]interface{}); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				dc.ResponseTypes = append(dc.ResponseTypes, s)
			}
		}
	}
	if s, ok := meta["token_endpoint_auth_method"].(string); ok {
		if s == "none" {
			dc.Public = true
		}
		// Note: token endpoint auth method may be stored in external attestation config or handled separately
	}
	if s, ok := meta["scope"].(string); ok {
		dc.Scopes = strings.Split(s, " ")
	}
	if arr, ok := meta["audience"].([]interface{}); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				dc.Audience = append(dc.Audience, s)
			}
		}
	}

	cc := &store.CustomClient{DefaultClient: dc}
	cc.MetadataDocumentLocation = location
	cc.MetadataDocumentExpiresAt = expires.Unix()
	cc.MetadataDocumentUpdatedAt = updatedAt.Unix()
	cc.DiscoveredByMetadataDocument = true

	return cc, nil
}

// RegisterClientFromMetadata fetches metadata and registers the client using provided storage
func RegisterClientFromMetadata(ctx context.Context, cfg *config.Config, storage store.Storage, location string) (*store.CustomClient, error) {
	// Parse URL and enforce allowlist if enabled
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}

	if !isHostAllowlisted(u, cfg) {
		return nil, fmt.Errorf("client metadata host %s not allowlisted", u.Hostname())
	}

	// Rate limit fetches per host to prevent abuse
	if err := enforceFetchRateLimit(u, cfg); err != nil {
		return nil, err
	}

	// Check existing client and cached metadata expiry
	if existing, err := storage.GetClient(ctx, location); err == nil {
		if cc, ok := existing.(*store.CustomClient); ok && cc.DiscoveredByMetadataDocument {
			if cc.MetadataDocumentExpiresAt > time.Now().Unix() && !cfg.CIMD.AlwaysRetrieved {
				// Still valid cache; return without fetching
				return cc, nil
			}
		}
	}

	meta, expires, updatedAt, err := FetchMetadata(ctx, location)
	if err != nil {
		return nil, err
	}

	// Cap expiry based on configuration
	if cfg != nil && cfg.CIMD.CacheMaxSeconds > 0 {
		capT := time.Now().Add(time.Duration(cfg.CIMD.CacheMaxSeconds) * time.Second)
		if expires.After(capT) {
			expires = capT
		}
	}

	if err := ValidateMetadata(meta, location); err != nil {
		return nil, err
	}

	// Apply metadata policy checks if configured
	if err := ValidateMetadataPolicy(meta, cfg); err != nil {
		return nil, err
	}

	client, err := CreateClientFromMetadata(meta, location, expires, updatedAt)
	if err != nil {
		return nil, err
	}

	// Try create; if client exists, update instead
	if err := storage.CreateClient(ctx, client); err != nil {
		// Attempt to update existing client
		if err2 := storage.UpdateClient(ctx, client.ID, client); err2 != nil {
			return nil, err
		}
	}

	return client, nil
}
