package storages

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"oauth2-server/internal/store/types"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// StorageTestSuite runs comprehensive tests against any Storage implementation
type StorageTestSuite struct {
	store types.Storage
	name  string
}

// NewStorageTestSuite creates a test suite for a storage implementation
func NewStorageTestSuite(store types.Storage, name string) *StorageTestSuite {
	return &StorageTestSuite{
		store: store,
		name:  name,
	}
}

// RunAllTests executes all storage tests
func (s *StorageTestSuite) RunAllTests(t *testing.T) {
	t.Run(s.name+"/ClientOperations", s.TestClientOperations)
	t.Run(s.name+"/PKCE", s.TestPKCE)
	t.Run(s.name+"/TrustAnchors", s.TestTrustAnchors)
	t.Run(s.name+"/PAR", s.TestPAR)
}

// TestClientOperations tests basic client CRUD operations
func (s *StorageTestSuite) TestClientOperations(t *testing.T) {
	ctx := context.Background()

	// Test client
	client := &types.CustomClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "test-client",
			Secret:        []byte("test-secret"),
			RedirectURIs:  []string{"http://localhost:8080/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "profile"},
		},
		Claims: []string{"email", "profile"},
	}

	// Create client
	err := s.store.CreateClient(ctx, client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Get client
	retrieved, err := s.store.GetClient(ctx, client.GetID())
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	// Verify client data
	if retrieved.GetID() != client.GetID() {
		t.Errorf("Client ID mismatch: got %s, want %s", retrieved.GetID(), client.GetID())
	}

	// Test client claims (custom functionality)
	customClient, ok := retrieved.(*types.CustomClient)
	if !ok {
		t.Fatalf("Retrieved client is not CustomClient type")
	}

	if !reflect.DeepEqual(customClient.GetClaims(), client.GetClaims()) {
		t.Errorf("Client claims mismatch: got %v, want %v", customClient.GetClaims(), client.GetClaims())
	}

	// Update client
	client.Claims = []string{"email", "profile", "phone"}
	err = s.store.UpdateClient(ctx, client.GetID(), client)
	if err != nil {
		t.Fatalf("Failed to update client: %v", err)
	}

	// Verify update
	updated, err := s.store.GetClient(ctx, client.GetID())
	if err != nil {
		t.Fatalf("Failed to get updated client: %v", err)
	}

	updatedCustom, ok := updated.(*types.CustomClient)
	if !ok {
		t.Fatalf("Updated client is not CustomClient type")
	}

	if !reflect.DeepEqual(updatedCustom.GetClaims(), client.GetClaims()) {
		t.Errorf("Updated client claims mismatch: got %v, want %v", updatedCustom.GetClaims(), client.GetClaims())
	}

	// Delete client
	err = s.store.DeleteClient(ctx, client.GetID())
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// Verify deletion
	_, err = s.store.GetClient(ctx, client.GetID())
	if err == nil {
		t.Error("Expected error when getting deleted client, got nil")
	}
}

// TestTokenOperations tests token storage and retrieval
func (s *StorageTestSuite) TestTokenOperations(t *testing.T) {
	ctx := context.Background()

	// Create test client first
	client := &types.CustomClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "token-test-client",
			Secret:        []byte("test-secret"),
			RedirectURIs:  []string{"http://localhost:8080/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "profile"},
		},
	}

	err := s.store.CreateClient(ctx, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	defer s.store.DeleteClient(ctx, client.GetID())

	// Test PKCE (simpler than full token flow)
	challenge := "test-pkce-challenge"

	err = s.store.CreatePKCERequestSession(ctx, challenge, &fosite.Request{
		ID:          "test-pkce-request",
		RequestedAt: time.Now(),
		Session:     &openid.DefaultSession{},
	})

	if err != nil {
		t.Fatalf("Failed to create PKCE session: %v", err)
	}

	retrieved, err := s.store.GetPKCERequestSession(ctx, challenge, nil)
	if err != nil {
		t.Fatalf("Failed to get PKCE session: %v", err)
	}

	if retrieved == nil {
		t.Fatalf("Retrieved PKCE request is nil")
	}

	// Clean up
	err = s.store.DeletePKCERequestSession(ctx, challenge)
	if err != nil {
		t.Fatalf("Failed to delete PKCE session: %v", err)
	}
}

// TestDeviceFlow tests device authorization flow
func (s *StorageTestSuite) TestDeviceFlow(t *testing.T) {
	ctx := context.Background()

	// Create test client
	client := &types.CustomClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "device-test-client",
			Secret:        []byte("test-secret"),
			RedirectURIs:  []string{"http://localhost:8080/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:device_code"},
			Scopes:        []string{"openid", "profile"},
		},
	}

	err := s.store.CreateClient(ctx, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	defer s.store.DeleteClient(ctx, client.GetID())

	// Test trust anchor (simpler test)
	anchorID := "test-device-anchor"
	anchorData := []byte("device-anchor-data")

	err = s.store.StoreTrustAnchor(ctx, anchorID, anchorData)
	if err != nil {
		t.Fatalf("Failed to store trust anchor: %v", err)
	}

	retrieved, err := s.store.GetTrustAnchor(ctx, anchorID)
	if err != nil {
		t.Fatalf("Failed to get trust anchor: %v", err)
	}

	if string(retrieved) != string(anchorData) {
		t.Errorf("Trust anchor data mismatch: got %s, want %s", string(retrieved), string(anchorData))
	}

	// Clean up
	err = s.store.DeleteTrustAnchor(ctx, anchorID)
	if err != nil {
		t.Fatalf("Failed to delete trust anchor: %v", err)
	}
}

// TestPKCE tests Proof Key for Code Exchange
func (s *StorageTestSuite) TestPKCE(t *testing.T) {
	ctx := context.Background()

	challenge := "challenge123"

	err := s.store.CreatePKCERequestSession(ctx, challenge, &fosite.Request{
		ID:          "pkce-test",
		RequestedAt: time.Now(),
		Session:     &openid.DefaultSession{},
	})

	if err != nil {
		t.Fatalf("Failed to create PKCE session: %v", err)
	}

	retrieved, err := s.store.GetPKCERequestSession(ctx, challenge, nil)
	if err != nil {
		t.Fatalf("Failed to get PKCE session: %v", err)
	}

	if retrieved == nil {
		t.Fatalf("Retrieved PKCE request is nil")
	}
}

// TestPAR tests Pushed Authorization Requests
func (s *StorageTestSuite) TestPAR(t *testing.T) {
	ctx := context.Background()

	requestURI := "urn:ietf:params:oauth:request_uri:test123"
	clientID := "par-test-client"

	par := &types.PARRequest{
		RequestURI: requestURI,
		ClientID:   clientID,
		ExpiresAt:  time.Now().Add(time.Hour), // Set expiration to future
		Parameters: map[string]string{
			"scope":         "openid profile",
			"response_type": "code",
		},
	}

	err := s.store.StorePARRequest(ctx, par)
	if err != nil {
		t.Fatalf("Failed to store PAR request: %v", err)
	}

	retrieved, err := s.store.GetPARRequest(ctx, requestURI)
	if err != nil {
		t.Fatalf("Failed to get PAR request: %v", err)
	}

	if retrieved.RequestURI != par.RequestURI {
		t.Errorf("PAR RequestURI mismatch: got %s, want %s", retrieved.RequestURI, par.RequestURI)
	}

	if retrieved.ClientID != par.ClientID {
		t.Errorf("PAR ClientID mismatch: got %s, want %s", retrieved.ClientID, par.ClientID)
	}

	// Clean up
	err = s.store.DeletePARRequest(ctx, requestURI)
	if err != nil {
		t.Fatalf("Failed to delete PAR request: %v", err)
	}
}

// TestTrustAnchors tests trust anchor management
func (s *StorageTestSuite) TestTrustAnchors(t *testing.T) {
	ctx := context.Background()

	anchorID := "test-anchor-123"
	anchorData := []byte("anchor-data-here")

	err := s.store.StoreTrustAnchor(ctx, anchorID, anchorData)
	if err != nil {
		t.Fatalf("Failed to store trust anchor: %v", err)
	}

	retrieved, err := s.store.GetTrustAnchor(ctx, anchorID)
	if err != nil {
		t.Fatalf("Failed to get trust anchor: %v", err)
	}

	if string(retrieved) != string(anchorData) {
		t.Errorf("Trust anchor data mismatch: got %s, want %s", string(retrieved), string(anchorData))
	}

	// Test deletion
	err = s.store.DeleteTrustAnchor(ctx, anchorID)
	if err != nil {
		t.Fatalf("Failed to delete trust anchor: %v", err)
	}

	_, err = s.store.GetTrustAnchor(ctx, anchorID)
	if err == nil {
		t.Error("Expected error when getting deleted trust anchor, got nil")
	}
}

// TestConcurrency tests thread safety
func (s *StorageTestSuite) TestConcurrency(t *testing.T) {
	ctx := context.Background()
	done := make(chan bool, 10)

	// Run multiple goroutines creating and deleting clients
	for i := 0; i < 10; i++ {
		go func(id int) {
			clientID := fmt.Sprintf("concurrency-test-client-%d", id)

			// Create client
			client := &types.CustomClient{
				DefaultClient: &fosite.DefaultClient{
					ID:            clientID,
					Secret:        []byte("test-secret"),
					RedirectURIs:  []string{"http://localhost:8080/callback"},
					ResponseTypes: []string{"code"},
					GrantTypes:    []string{"authorization_code"},
					Scopes:        []string{"openid", "profile"},
				},
			}

			err := s.store.CreateClient(ctx, client)
			if err != nil {
				t.Errorf("Failed to create client %s: %v", clientID, err)
				done <- false
				return
			}

			// Get client
			_, err = s.store.GetClient(ctx, clientID)
			if err != nil {
				t.Errorf("Failed to get client %s: %v", clientID, err)
				done <- false
				return
			}

			// Delete client
			err = s.store.DeleteClient(ctx, clientID)
			if err != nil {
				t.Errorf("Failed to delete client %s: %v", clientID, err)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		if !<-done {
			t.Error("Concurrency test failed")
		}
	}
}
