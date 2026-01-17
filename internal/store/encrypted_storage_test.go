package store

import (
	"context"
	"encoding/json"
	"testing"

	"oauth2-server/internal/store/storages"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

func TestEncryptedStorage_Integration(t *testing.T) {
	// Create SQLite store with in-memory database for testing
	logger := logrus.New()
	sqliteStore, err := storages.NewSQLiteStore(":memory:", logger)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer sqliteStore.Close()

	// Create secret manager
	key := "abcdefghijklmnopqrstuvwxyz123456" // 32 bytes
	sm := NewSecretManager([]byte(key))

	// Test data
	clientID := "test-client-123"
	secret := "super-secret-password-123"
	attestationConfig := &config.ClientAttestationConfig{
		ClientID:       clientID,
		AllowedMethods: []string{"attest_jwt_client_auth"},
		TrustAnchors:   []string{"test-anchor"},
		RequiredLevel:  "medium",
	}

	// First create a client in the store (required for the encrypted storage to work)
	testClient := &fosite.DefaultClient{
		ID: clientID,
	}
	err = sqliteStore.CreateClient(context.TODO(), testClient)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Encrypt secret and store it
	encryptedSecret, err := sm.EncryptSecret(secret)
	if err != nil {
		t.Fatalf("Failed to encrypt secret: %v", err)
	}

	err = sqliteStore.StoreClientSecret(context.TODO(), clientID, encryptedSecret)
	if err != nil {
		t.Fatalf("Failed to store encrypted client secret: %v", err)
	}

	// Store attestation config
	err = sqliteStore.StoreAttestationConfig(context.TODO(), clientID, attestationConfig)
	if err != nil {
		t.Fatalf("Failed to store attestation config: %v", err)
	}

	// Retrieve and decrypt secret
	retrievedEncryptedSecret, err := sqliteStore.GetClientSecret(context.TODO(), clientID)
	if err != nil {
		t.Fatalf("Failed to retrieve encrypted client secret: %v", err)
	}

	retrievedSecret, err := sm.DecryptSecret(retrievedEncryptedSecret)
	if err != nil {
		t.Fatalf("Failed to decrypt retrieved secret: %v", err)
	}

	if retrievedSecret != secret {
		t.Fatalf("Retrieved secret does not match. Got: %s, Expected: %s", retrievedSecret, secret)
	}

	// Retrieve and verify attestation config
	retrievedConfig, err := sqliteStore.GetAttestationConfig(context.TODO(), clientID)
	if err != nil {
		t.Fatalf("Failed to retrieve attestation config: %v", err)
	}

	// Compare the configs
	retrievedJSON, err := json.Marshal(retrievedConfig)
	if err != nil {
		t.Fatalf("Failed to marshal retrieved config: %v", err)
	}

	expectedJSON, err := json.Marshal(attestationConfig)
	if err != nil {
		t.Fatalf("Failed to marshal expected config: %v", err)
	}

	if string(retrievedJSON) != string(expectedJSON) {
		t.Fatalf("Retrieved config does not match. Got: %s, Expected: %s", string(retrievedJSON), string(expectedJSON))
	}
}
