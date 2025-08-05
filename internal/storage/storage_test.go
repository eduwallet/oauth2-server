package storage

import (
	"os"
	"testing"
	"time"

	"oauth2-server/internal/config"
)

func TestSQLiteStorage(t *testing.T) {
	// Create a temporary database file
	tmpFile := "/tmp/test_oauth2.db"
	defer os.Remove(tmpFile)

	storage, err := NewSQLiteStorage(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer storage.Close()

	// Test storing and retrieving an auth code
	authReq := &AuthorizeRequest{
		ClientID:     "test-client",
		ResponseType: "code",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       []string{"read", "write"},
		State:        "test-state",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	err = storage.StoreAuthCode("test-code", authReq)
	if err != nil {
		t.Fatalf("Failed to store auth code: %v", err)
	}

	retrieved, err := storage.GetAuthCode("test-code")
	if err != nil {
		t.Fatalf("Failed to retrieve auth code: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Auth code not found")
	}

	if retrieved.ClientID != authReq.ClientID {
		t.Errorf("Expected ClientID %s, got %s", authReq.ClientID, retrieved.ClientID)
	}

	if !equalStringSlices(retrieved.Scopes, authReq.Scopes) {
		t.Errorf("Expected Scopes %v, got %v", authReq.Scopes, retrieved.Scopes)
	}

	// Test dynamic client storage
	clientConfig := &config.ClientConfig{
		ID:                      "test-dynamic-client",
		Secret:                  "test-secret",
		Name:                    "Test Dynamic Client",
		Description:             "A test dynamic client",
		RedirectURIs:            []string{"http://localhost:8080/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"read", "write"},
		Audience:                []string{"api.example.com"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Public:                  false,
		EnabledFlows:            []string{"authorization_code"},
	}

	err = storage.StoreDynamicClient(clientConfig.ID, clientConfig)
	if err != nil {
		t.Fatalf("Failed to store dynamic client: %v", err)
	}

	retrievedClient, err := storage.GetDynamicClient(clientConfig.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve dynamic client: %v", err)
	}

	if retrievedClient == nil {
		t.Fatal("Dynamic client not found")
	}

	if retrievedClient.Name != clientConfig.Name {
		t.Errorf("Expected client name %s, got %s", clientConfig.Name, retrievedClient.Name)
	}

	if len(retrievedClient.RedirectURIs) != len(clientConfig.RedirectURIs) {
		t.Errorf("Expected %d redirect URIs, got %d", len(clientConfig.RedirectURIs), len(retrievedClient.RedirectURIs))
	}

	// Test registration token storage
	err = storage.StoreRegistrationToken("test-reg-token", "test-client-id")
	if err != nil {
		t.Fatalf("Failed to store registration token: %v", err)
	}

	retrievedClientID, err := storage.GetClientIDByRegistrationToken("test-reg-token")
	if err != nil {
		t.Fatalf("Failed to retrieve client ID by registration token: %v", err)
	}

	if retrievedClientID != "test-client-id" {
		t.Errorf("Expected client ID %s, got %s", "test-client-id", retrievedClientID)
	}

	// Test device code storage
	deviceState := &DeviceCodeState{
		DeviceCodeResponse: &DeviceCodeResponse{
			DeviceCode:              "test-device-code",
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://example.com/device",
			VerificationURIComplete: "https://example.com/device?user_code=ABCD-EFGH",
			ExpiresIn:               600,
			Interval:                5,
		},
		ClientID:    "test-client",
		Scope:       "read write",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Authorized:  false,
		UserID:      "",
		AccessToken: "",
	}

	err = storage.StoreDeviceCode("test-device-code", deviceState)
	if err != nil {
		t.Fatalf("Failed to store device code: %v", err)
	}

	retrievedDeviceState, err := storage.GetDeviceCode("test-device-code")
	if err != nil {
		t.Fatalf("Failed to retrieve device code: %v", err)
	}

	if retrievedDeviceState == nil {
		t.Fatal("Device code not found")
	}

	if retrievedDeviceState.UserCode != deviceState.UserCode {
		t.Errorf("Expected user code %s, got %s", deviceState.UserCode, retrievedDeviceState.UserCode)
	}

	if retrievedDeviceState.Interval != deviceState.Interval {
		t.Errorf("Expected interval %d, got %d", deviceState.Interval, retrievedDeviceState.Interval)
	}

	// Test get device code by user code
	retrievedDeviceState2, deviceCode, err := storage.GetDeviceCodeByUserCode("ABCD-EFGH")
	if err != nil {
		t.Fatalf("Failed to retrieve device code by user code: %v", err)
	}

	if retrievedDeviceState2 == nil {
		t.Fatal("Device code not found by user code")
	}

	if deviceCode != "test-device-code" {
		t.Errorf("Expected device code %s, got %s", "test-device-code", deviceCode)
	}
}

func TestDialectDifferences(t *testing.T) {
	sqliteDialect := &SQLiteDialect{}
	postgresDialect := &PostgreSQLDialect{}

	// Test placeholder differences
	if sqliteDialect.Placeholder(1) != "?" {
		t.Errorf("SQLite should use ? placeholders, got %s", sqliteDialect.Placeholder(1))
	}

	if postgresDialect.Placeholder(1) != "$1" {
		t.Errorf("PostgreSQL should use $1 placeholders, got %s", postgresDialect.Placeholder(1))
	}

	// Test JSON type differences
	if sqliteDialect.GetJSONType() != "TEXT" {
		t.Errorf("SQLite should use TEXT for JSON, got %s", sqliteDialect.GetJSONType())
	}

	if postgresDialect.GetJSONType() != "JSONB" {
		t.Errorf("PostgreSQL should use JSONB for JSON, got %s", postgresDialect.GetJSONType())
	}

	// Test timestamp function differences
	if sqliteDialect.GetTimestampFunction() != "CURRENT_TIMESTAMP" {
		t.Errorf("SQLite should use CURRENT_TIMESTAMP, got %s", sqliteDialect.GetTimestampFunction())
	}

	if postgresDialect.GetTimestampFunction() != "NOW()" {
		t.Errorf("PostgreSQL should use NOW(), got %s", postgresDialect.GetTimestampFunction())
	}
}

func TestStorageFactory(t *testing.T) {
	// Test memory storage creation
	memConfig := &config.DatabaseConfig{Type: "memory"}
	storage, err := NewStorage(memConfig)
	if err != nil {
		t.Fatalf("Failed to create memory storage: %v", err)
	}
	defer storage.Close()

	// Test that it's actually a memory storage
	if _, ok := storage.(*MemoryStorage); !ok {
		t.Error("Expected MemoryStorage instance")
	}

	// Test SQLite storage creation
	tmpFile := "/tmp/test_factory.db"
	defer os.Remove(tmpFile)

	sqliteConfig := &config.DatabaseConfig{
		Type:       "sqlite",
		SQLitePath: tmpFile,
	}
	storage2, err := NewStorage(sqliteConfig)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer storage2.Close()

	// Test that it's actually a SQLite storage
	if _, ok := storage2.(*SQLiteStorage); !ok {
		t.Error("Expected SQLiteStorage instance")
	}
}
