package storages

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"oauth2-server/internal/store/types"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

// PropertyTestSuite runs property-based tests with random data
type PropertyTestSuite struct {
	store types.Storage
	name  string
	rand  *rand.Rand
}

// NewPropertyTestSuite creates a property test suite
func NewPropertyTestSuite(store types.Storage, name string) *PropertyTestSuite {
	return &PropertyTestSuite{
		store: store,
		name:  name,
		rand:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// TestRandomClientOperations tests client operations with random data
func (p *PropertyTestSuite) TestRandomClientOperations(t *testing.T) {
	ctx := context.Background()

	// Test with multiple random clients
	for i := 0; i < 10; i++ {
		clientID := fmt.Sprintf("prop-test-client-%d-%d", i, p.rand.Int63())
		client := p.generateRandomClient(clientID)

		// Create client
		err := p.store.CreateClient(ctx, client)
		if err != nil {
			t.Fatalf("Failed to create random client %s: %v", clientID, err)
		}

		// Retrieve and verify
		retrieved, err := p.store.GetClient(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to get random client %s: %v", clientID, err)
		}

		p.verifyClientEqual(t, client, retrieved)

		// Update with random changes
		updatedClient := p.generateRandomClient(clientID) // Same ID, different data
		err = p.store.UpdateClient(ctx, clientID, updatedClient)
		if err != nil {
			t.Fatalf("Failed to update random client %s: %v", clientID, err)
		}

		// Verify update
		updatedRetrieved, err := p.store.GetClient(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to get updated random client %s: %v", clientID, err)
		}

		p.verifyClientEqual(t, updatedClient, updatedRetrieved)

		// Clean up
		err = p.store.DeleteClient(ctx, clientID)
		if err != nil {
			t.Fatalf("Failed to delete random client %s: %v", clientID, err)
		}
	}
}

// TestRandomTokenOperations tests token operations with random data
func (p *PropertyTestSuite) TestRandomTokenOperations(t *testing.T) {
	ctx := context.Background()

	// Create a test client first
	client := &types.CustomClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "prop-test-token-client",
			Secret:        []byte("test-secret"),
			RedirectURIs:  []string{"http://localhost:8080/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "profile"},
		},
	}

	err := p.store.CreateClient(ctx, client)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	defer p.store.DeleteClient(ctx, client.GetID())

	// Test random authorization codes
	for i := 0; i < 5; i++ {
		authCodeID := fmt.Sprintf("prop-auth-code-%d-%d", i, p.rand.Int63())
		authCode := p.generateRandomRequest(authCodeID, client)

		err := p.store.CreateAuthorizeCodeSession(ctx, authCodeID, authCode)
		if err != nil {
			t.Fatalf("Failed to create random auth code %s: %v", authCodeID, err)
		}

		retrieved, err := p.store.GetAuthorizeCodeSession(ctx, authCodeID, nil)
		if err != nil {
			t.Fatalf("Failed to get random auth code %s: %v", authCodeID, err)
		}

		if retrieved.GetID() != authCodeID {
			t.Errorf("Auth code ID mismatch: got %s, want %s", retrieved.GetID(), authCodeID)
		}
	}

	// Test random access tokens
	for i := 0; i < 5; i++ {
		tokenID := fmt.Sprintf("prop-access-token-%d-%d", i, p.rand.Int63())
		token := p.generateRandomRequest(tokenID, client)

		err := p.store.CreateAccessTokenSession(ctx, tokenID, token)
		if err != nil {
			t.Fatalf("Failed to create random access token %s: %v", tokenID, err)
		}

		retrieved, err := p.store.GetAccessTokenSession(ctx, tokenID, nil)
		if err != nil {
			t.Fatalf("Failed to get random access token %s: %v", tokenID, err)
		}

		if retrieved.GetID() != tokenID {
			t.Errorf("Access token ID mismatch: got %s, want %s", retrieved.GetID(), tokenID)
		}
	}
}

// generateRandomClient creates a client with random data
func (p *PropertyTestSuite) generateRandomClient(clientID string) *types.CustomClient {
	scopes := []string{"openid", "profile", "email", "phone", "address"}
	claims := []string{"email", "profile", "phone", "address"}

	// Randomly select subsets
	selectedScopes := make([]string, 0)
	selectedClaims := make([]string, 0)

	for _, scope := range scopes {
		if p.rand.Float32() < 0.7 { // 70% chance to include
			selectedScopes = append(selectedScopes, scope)
		}
	}

	for _, claim := range claims {
		if p.rand.Float32() < 0.6 { // 60% chance to include
			selectedClaims = append(selectedClaims, claim)
		}
	}

	return &types.CustomClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte(fmt.Sprintf("secret-%d", p.rand.Int63())),
			RedirectURIs:  []string{fmt.Sprintf("http://localhost:%d/callback", 8080+p.rand.Intn(1000))},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        selectedScopes,
		},
		Claims:              selectedClaims,
		ForceAuthentication: p.rand.Float32() < 0.5,
		ForceConsent:        p.rand.Float32() < 0.3,
	}
}

// generateRandomRequest creates a request with random data
func (p *PropertyTestSuite) generateRandomRequest(requestID string, client fosite.Client) *fosite.Request {
	return &fosite.Request{
		ID:          requestID,
		RequestedAt: time.Now(),
		Client:      client,
	}
}

// verifyClientEqual checks if two clients are equivalent
func (p *PropertyTestSuite) verifyClientEqual(t *testing.T, expected, actual fosite.Client) {
	if expected.GetID() != actual.GetID() {
		t.Errorf("Client ID mismatch: got %s, want %s", actual.GetID(), expected.GetID())
	}

	// For CustomClient, check additional fields
	expectedCustom, ok1 := expected.(*types.CustomClient)
	actualCustom, ok2 := actual.(*types.CustomClient)

	if ok1 && ok2 {
		if len(expectedCustom.GetClaims()) != len(actualCustom.GetClaims()) {
			t.Errorf("Client claims length mismatch: got %d, want %d", len(actualCustom.GetClaims()), len(expectedCustom.GetClaims()))
		}
	}
}

// TestAllPropertyTests runs property tests against all storage backends
func TestAllPropertyTests(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	stores := []struct {
		name    string
		store   types.Storage
		cleanup func()
	}{
		{
			name: "SQLite",
			store: func() types.Storage {
				store, _ := NewSQLiteStore(":memory:", logger)
				return store
			}(),
			cleanup: func() {
				// SQLite cleanup would go here if needed
			},
		},
		{
			name:    "Memory",
			store:   NewMemoryStoreWrapper(storage.NewMemoryStore(), logger),
			cleanup: func() {},
		},
	}

	// Add PostgreSQL if available
	pgStore, err := NewPostgresStore("postgres://test:test@127.0.0.1/oauth2_test?sslmode=disable", logger)
	if err == nil {
		stores = append(stores, struct {
			name    string
			store   types.Storage
			cleanup func()
		}{
			name:    "PostgreSQL",
			store:   pgStore,
			cleanup: func() { pgStore.Close() },
		})
	} else {
		t.Logf("PostgreSQL not available for property testing: %v", err)
	}

	defer func() {
		for _, s := range stores {
			if s.cleanup != nil {
				s.cleanup()
			}
		}
	}()

	for _, storeInfo := range stores {
		t.Run(fmt.Sprintf("PropertyTests/%s", storeInfo.name), func(t *testing.T) {
			suite := NewPropertyTestSuite(storeInfo.store, storeInfo.name)
			suite.TestRandomClientOperations(t)
			suite.TestRandomTokenOperations(t)
		})
	}
}
