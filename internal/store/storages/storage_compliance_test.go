package storages

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"oauth2-server/internal/store/types"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

// TestAllStorageImplementations runs the complete test suite against all storage backends
func TestAllStorageImplementations(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise during tests

	storageBackends := []struct {
		name  string
		store func() (types.Storage, func(), error) // returns store, cleanup function, error
	}{
		{
			name: "SQLite",
			store: func() (types.Storage, func(), error) {
				store, err := NewSQLiteStore(":memory:", logger)
				if err != nil {
					return nil, nil, err
				}
				return store, func() { store.Close() }, nil
			},
		},
		{
			name: "Memory",
			store: func() (types.Storage, func(), error) {
				store := NewMemoryStoreWrapper(storage.NewMemoryStore(), logger)
				return store, func() {}, nil
			},
		},
		{
			name: "PostgreSQL",
			store: func() (types.Storage, func(), error) {
				// Use a test database URL - in real scenarios this would come from environment
				// For now, skip PostgreSQL tests if not available
				store, err := NewPostgresStore("postgres://test:test@127.0.0.1/oauth2_test?sslmode=disable", logger)
				if err != nil {
					// Return nil store to indicate PostgreSQL is not available
					// The test will skip this backend gracefully
					return nil, func() {}, nil
				}
				return store, func() { store.Close() }, nil
			},
		},
	}

	for _, backend := range storageBackends {
		t.Run(backend.name, func(t *testing.T) {
			store, cleanup, err := backend.store()
			if err != nil {
				t.Fatalf("Failed to create %s store: %v", backend.name, err)
			}
			if store == nil {
				t.Skipf("%s not available for testing", backend.name)
				return
			}
			defer cleanup()

			// Run the comprehensive test suite
			suite := NewStorageTestSuite(store, backend.name)
			suite.RunAllTests(t)
		})
	}
}

// TestStorageInterfaceCompliance ensures all storage implementations satisfy the Storage interface
func TestStorageInterfaceCompliance(t *testing.T) {
	stores := []interface{}{
		&SQLiteStore{},
		&PostgresStore{},
		&MemoryStoreWrapper{},
	}

	var storage types.Storage
	storageType := reflect.TypeOf(&storage).Elem()

	for _, store := range stores {
		storeType := reflect.TypeOf(store)
		if !storeType.Implements(storageType) {
			t.Errorf("Type %s does not implement Storage interface", storeType.String())
		}
	}
}

// TestGoldenFileCompatibility tests that all implementations produce identical serialized output
func TestGoldenFileCompatibility(t *testing.T) {
	// This test ensures that when the same data is stored and retrieved,
	// all implementations produce identical JSON serialization
	// This is crucial for data portability between storage backends

	logger := logrus.New()
	ctx := context.Background()

	// Test data that should serialize identically across all backends
	testClient := &types.CustomClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "golden-test-client",
			Secret:        []byte("golden-secret"),
			RedirectURIs:  []string{"http://localhost:8080/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "profile"},
		},
		Claims: []string{"email", "profile"},
	}

	stores := []struct {
		name    string
		store   types.Storage
		cleanup func()
	}{
		{"SQLite", nil, nil},
		{"Memory", nil, nil},
		{"PostgreSQL", nil, nil},
	}

	// Initialize stores
	sqliteStore, err := NewSQLiteStore(":memory:", logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	stores[0].store = sqliteStore
	stores[0].cleanup = func() { sqliteStore.Close() }

	memoryStore := NewMemoryStoreWrapper(storage.NewMemoryStore(), logger)
	stores[1].store = memoryStore
	stores[1].cleanup = func() {}

	// PostgreSQL - skip if not available
	pgStore, err := NewPostgresStore("postgres://test:test@127.0.0.1/oauth2_test?sslmode=disable", logger)
	if err == nil {
		stores[2].store = pgStore
		stores[2].cleanup = func() { pgStore.Close() }
	} else {
		t.Logf("PostgreSQL not available for golden file test: %v", err)
		stores[2].store = nil // Mark as unavailable
	}

	defer func() {
		for _, s := range stores {
			if s.cleanup != nil {
				s.cleanup()
			}
		}
	}()

	var goldenClientJSON string

	for i, storeInfo := range stores {
		if storeInfo.store == nil {
			continue // Skip unavailable stores
		}

		// Create client
		err := storeInfo.store.CreateClient(ctx, testClient)
		if err != nil {
			t.Fatalf("Failed to create client in %s: %v", storeInfo.name, err)
		}

		// Retrieve client
		retrieved, err := storeInfo.store.GetClient(ctx, testClient.GetID())
		if err != nil {
			t.Fatalf("Failed to retrieve client from %s: %v", storeInfo.name, err)
		}

		// Serialize to JSON
		jsonBytes, err := json.Marshal(retrieved)
		if err != nil {
			t.Fatalf("Failed to marshal client from %s: %v", storeInfo.name, err)
		}

		currentJSON := string(jsonBytes)

		if i == 0 {
			// First store sets the golden standard
			goldenClientJSON = currentJSON
		} else {
			// Subsequent stores must match
			if currentJSON != goldenClientJSON {
				t.Errorf("JSON serialization mismatch for %s:\nExpected: %s\nGot: %s",
					storeInfo.name, goldenClientJSON, currentJSON)
			}
		}

		// Clean up
		err = storeInfo.store.DeleteClient(ctx, testClient.GetID())
		if err != nil {
			t.Fatalf("Failed to delete client from %s: %v", storeInfo.name, err)
		}
	}
}
