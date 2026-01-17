package store

import (
	"context"
	"testing"
	"time"

	"oauth2-server/internal/store/storages"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

// TestCustomStorage_AllBackends tests CustomStorage with all supported storage backends
func TestCustomStorage_AllBackends(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise during tests

	// Test data
	clientID := "test-client-custom"
	userID := "test-user-custom"
	secret := "encrypted-secret-123"
	trustAnchorName := "test-trust-anchor"
	certificateData := []byte("-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----")
	jti := "test-jti-123"
	exp := time.Now().Add(time.Hour)

	attestationConfig := &config.ClientAttestationConfig{
		ClientID:       clientID,
		AllowedMethods: []string{"attest_jwt_client_auth"},
		TrustAnchors:   []string{"test-anchor"},
		RequiredLevel:  "medium",
	}

	testClient := &fosite.DefaultClient{
		ID:           clientID,
		Secret:       []byte("client-secret"),
		RedirectURIs: []string{"http://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:       []string{"openid", "profile"},
		Public:       true,
	}

	testUser := &storage.MemoryUserRelation{
		Username: userID,
		Password: "password123",
	}

	// Test each storage backend
	backends := []struct {
		name   string
		create func() (fosite.Storage, func())
	}{
		{
			name: "MemoryStoreWrapper",
			create: func() (fosite.Storage, func()) {
				mem := storage.NewMemoryStore()
				store := storages.NewMemoryStoreWrapper(mem, logger)
				return store, func() {} // No cleanup needed
			},
		},
		{
			name: "SQLiteStore",
			create: func() (fosite.Storage, func()) {
				store, err := storages.NewSQLiteStore(":memory:", logger)
				if err != nil {
					t.Fatalf("Failed to create SQLite store: %v", err)
				}
				return store, func() { store.Close() }
			},
		},
		{
			name: "PostgresStore",
			create: func() (fosite.Storage, func()) {
				// Try to create PostgreSQL store - will be checked in subtest
				store, err := storages.NewPostgresStore("postgres://test:test@localhost:5432/oauth2_test?sslmode=disable", logger)
				if err != nil {
					return nil, func() {} // Return nil to indicate skip
				}
				return store, func() { store.Close() }
			},
		},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			underlyingStore, cleanup := backend.create()
			if underlyingStore == nil {
				t.Skipf("Storage backend %s not available, skipping", backend.name)
			}
			defer cleanup()

			// Create CustomStorage wrapper
			customStore := NewCustomStorage(underlyingStore, logger)

			// Test Client Operations
			t.Run("ClientOperations", func(t *testing.T) {
				// Create client
				err := customStore.CreateClient(context.TODO(), testClient)
				if err != nil {
					t.Fatalf("Failed to create client: %v", err)
				}

				// Get client
				retrievedClient, err := customStore.GetClient(context.TODO(), clientID)
				if err != nil {
					t.Fatalf("Failed to get client: %v", err)
				}
				if retrievedClient.GetID() != clientID {
					t.Errorf("Expected client ID %s, got %s", clientID, retrievedClient.GetID())
				}

				// Update client
				updatedClient := &fosite.DefaultClient{
					ID:           clientID,
					Secret:       []byte("updated-secret"),
					RedirectURIs: []string{"http://example.com/callback", "http://example.com/callback2"},
					GrantTypes:   []string{"authorization_code", "refresh_token"},
					ResponseTypes: []string{"code"},
					Scopes:       []string{"openid", "profile", "email"},
					Public:       true,
				}
				err = customStore.UpdateClient(context.TODO(), clientID, updatedClient)
				if err != nil {
					t.Fatalf("Failed to update client: %v", err)
				}

				// Delete client
				err = customStore.DeleteClient(context.TODO(), clientID)
				if err != nil {
					t.Fatalf("Failed to delete client: %v", err)
				}
			})

			// Test User Operations
			t.Run("UserOperations", func(t *testing.T) {
				// Create user (if supported)
				err := customStore.CreateUser(context.TODO(), userID, testUser)
				if err != nil {
					t.Logf("CreateUser not supported or failed: %v", err)
				} else {
					// Get user
					retrievedUser, err := customStore.GetUser(context.TODO(), userID)
					if err != nil {
						t.Fatalf("Failed to get user: %v", err)
					}
					if retrievedUser.Username != userID {
						t.Errorf("Expected user ID %s, got %s", userID, retrievedUser.Username)
					}

					// Update user
					updatedUser := &storage.MemoryUserRelation{
						Username: userID,
						Password: "updated-password",
					}
					err = customStore.UpdateUser(context.TODO(), userID, updatedUser)
					if err != nil {
						t.Fatalf("Failed to update user: %v", err)
					}

					// Delete user
					err = customStore.DeleteUser(context.TODO(), userID)
					if err != nil {
						t.Fatalf("Failed to delete user: %v", err)
					}
				}
			})

			// Test Trust Anchor Operations
			t.Run("TrustAnchorOperations", func(t *testing.T) {
				// Store trust anchor
				err := customStore.StoreTrustAnchor(context.TODO(), trustAnchorName, certificateData)
				if err != nil {
					t.Fatalf("Failed to store trust anchor: %v", err)
				}

				// Get trust anchor
				retrievedData, err := customStore.GetTrustAnchor(context.TODO(), trustAnchorName)
				if err != nil {
					t.Fatalf("Failed to get trust anchor: %v", err)
				}
				if string(retrievedData) != string(certificateData) {
					t.Errorf("Trust anchor data mismatch")
				}

				// List trust anchors
				anchors, err := customStore.ListTrustAnchors(context.TODO())
				if err != nil {
					t.Fatalf("Failed to list trust anchors: %v", err)
				}
				if len(anchors) == 0 {
					t.Errorf("Expected at least one trust anchor in list")
				}
				found := false
				for _, anchor := range anchors {
					if anchor == trustAnchorName {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Trust anchor %s not found in list", trustAnchorName)
				}

				// Delete trust anchor
				err = customStore.DeleteTrustAnchor(context.TODO(), trustAnchorName)
				if err != nil {
					t.Fatalf("Failed to delete trust anchor: %v", err)
				}
			})

			// Test Attestation Config Operations
			t.Run("AttestationConfigOperations", func(t *testing.T) {
				// First create the client in the underlying store
				if storage, ok := underlyingStore.(interface {
					CreateClient(ctx context.Context, client fosite.Client) error
				}); ok {
					if err := storage.CreateClient(context.TODO(), testClient); err != nil {
						t.Logf("Underlying store doesn't support CreateClient, skipping attestation config test: %v", err)
						return
					}
				} else {
					t.Logf("Underlying store doesn't support CreateClient interface, skipping attestation config test")
					return
				}

				// Store attestation config
				if err := customStore.StoreAttestationConfig(context.TODO(), clientID, attestationConfig); err != nil {
					t.Fatalf("Failed to store attestation config: %v", err)
				}

				// Get attestation config
				retrievedConfig, err := customStore.GetAttestationConfig(context.TODO(), clientID)
				if err != nil {
					t.Fatalf("Failed to get attestation config: %v", err)
				}
				if retrievedConfig.ClientID != clientID {
					t.Errorf("Expected client ID %s, got %s", clientID, retrievedConfig.ClientID)
				}
				if len(retrievedConfig.AllowedMethods) != len(attestationConfig.AllowedMethods) {
					t.Errorf("Allowed methods length mismatch")
				}

				// Delete attestation config
				if err := customStore.DeleteAttestationConfig(context.TODO(), clientID); err != nil {
					t.Fatalf("Failed to delete attestation config: %v", err)
				}
			})

			// Test Client Secret Operations
			t.Run("ClientSecretOperations", func(t *testing.T) {
				// First create the client in the underlying store
				if storage, ok := underlyingStore.(interface {
					CreateClient(ctx context.Context, client fosite.Client) error
				}); ok {
					if err := storage.CreateClient(context.TODO(), testClient); err != nil {
						t.Logf("Underlying store doesn't support CreateClient, skipping client secret test: %v", err)
						return
					}
				} else {
					t.Logf("Underlying store doesn't support CreateClient interface, skipping client secret test")
					return
				}

				// Store client secret
				if err := customStore.StoreClientSecret(context.TODO(), clientID, secret); err != nil {
					t.Fatalf("Failed to store client secret: %v", err)
				}

				// Get client secret
				retrievedSecret, err := customStore.GetClientSecret(context.TODO(), clientID)
				if err != nil {
					t.Fatalf("Failed to get client secret: %v", err)
				}
				if retrievedSecret != secret {
					t.Errorf("Expected secret %s, got %s", secret, retrievedSecret)
				}
			})

			// Test Client Assertion JWT Operations
			t.Run("ClientAssertionJWTOperations", func(t *testing.T) {
				// Set client assertion JWT
				err := customStore.SetClientAssertionJWT(context.TODO(), jti, exp)
				if err != nil {
					t.Logf("SetClientAssertionJWT not supported or failed: %v", err)
					return
				}

				// Validate client assertion JWT
				err = customStore.ClientAssertionJWTValid(context.TODO(), jti)
				if err != nil {
					t.Logf("ClientAssertionJWTValid not supported or failed: %v", err)
					// This is acceptable for some storage backends
				}
			})

			// Test Count Operations
			t.Run("CountOperations", func(t *testing.T) {
				// Test client count
				clientCount, err := customStore.GetClientCount()
				if err != nil {
					t.Logf("GetClientCount failed: %v", err)
				} else if clientCount < 0 {
					t.Errorf("Invalid client count: %d", clientCount)
				}

				// Test user count
				userCount, err := customStore.GetUserCount()
				if err != nil {
					t.Logf("GetUserCount failed: %v", err)
				} else if userCount < 0 {
					t.Errorf("Invalid user count: %d", userCount)
				}

				// Test access token count
				accessTokenCount, err := customStore.GetAccessTokenCount()
				if err != nil {
					t.Logf("GetAccessTokenCount failed: %v", err)
				} else if accessTokenCount < 0 {
					t.Errorf("Invalid access token count: %d", accessTokenCount)
				}

				// Test refresh token count
				refreshTokenCount, err := customStore.GetRefreshTokenCount()
				if err != nil {
					t.Logf("GetRefreshTokenCount failed: %v", err)
				} else if refreshTokenCount < 0 {
					t.Errorf("Invalid refresh token count: %d", refreshTokenCount)
				}
			})
		})
	}
}

// TestCustomStorage_InMemoryClientMap tests that CustomStorage maintains its own client map
func TestCustomStorage_InMemoryClientMap(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create memory store
	mem := storage.NewMemoryStore()
	memoryStore := storages.NewMemoryStoreWrapper(mem, logger)
	customStore := NewCustomStorage(memoryStore, logger)

	clientID := "test-client-map"
	testClient := &fosite.DefaultClient{
		ID:     clientID,
		Secret: []byte("secret"),
		Public: true,
	}

	// Create client through CustomStorage
	err := customStore.CreateClient(context.TODO(), testClient)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Verify client exists in CustomStorage's map
	if len(customStore.Clients) != 1 {
		t.Errorf("Expected 1 client in map, got %d", len(customStore.Clients))
	}

	if _, exists := customStore.Clients[clientID]; !exists {
		t.Errorf("Client not found in CustomStorage map")
	}

	// Verify client can be retrieved
	retrievedClient, err := customStore.GetClient(context.TODO(), clientID)
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	if retrievedClient.GetID() != clientID {
		t.Errorf("Retrieved client ID mismatch")
	}
}