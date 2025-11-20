package store

import (
	"context"
	"fmt"
	"log"
	"time"

	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// CustomStorage wraps our storage but provides custom client management
type CustomStorage struct {
	Storage fosite.Storage                        // Embed fosite.Storage to get all interface implementations
	Clients map[string]fosite.Client              // Keep clients in memory for custom management
	Users   map[string]storage.MemoryUserRelation // Keep users in memory for custom management
}

// NewCustomStorage creates a new CustomStorage instance
func NewCustomStorage(underlyingStore fosite.Storage) *CustomStorage {
	return &CustomStorage{
		Storage: underlyingStore,
		Clients: make(map[string]fosite.Client),
		Users:   make(map[string]storage.MemoryUserRelation),
	}
}

// Implement store.Storage interface methods by delegating to underlying store
func (s *CustomStorage) CreateClient(ctx context.Context, client fosite.Client) error {
	log.Printf("🔍 CustomStorage.CreateClient: adding client %s to map and persisting to storage", client.GetID())

	// Store in memory map for fast access
	s.Clients[client.GetID()] = client

	// Also persist to underlying storage (cast to store.Storage interface)
	if storage, ok := s.Storage.(interface {
		CreateClient(ctx context.Context, client fosite.Client) error
	}); ok {
		if err := storage.CreateClient(ctx, client); err != nil {
			log.Printf("❌ CustomStorage.CreateClient: failed to persist client %s to storage: %v", client.GetID(), err)
			return err
		}
	} else {
		log.Printf("⚠️ CustomStorage.CreateClient: underlying storage does not support CreateClient")
	}

	log.Printf("✅ CustomStorage.CreateClient: client %s added to map and persisted (total clients: %d)", client.GetID(), len(s.Clients))
	return nil
}

func (s *CustomStorage) UpdateClient(ctx context.Context, id string, client fosite.Client) error {
	log.Printf("🔍 CustomStorage.UpdateClient: updating client %s in map and storage", id)

	// Update in memory map
	s.Clients[id] = client

	// Also update in underlying storage
	if storage, ok := s.Storage.(interface {
		UpdateClient(ctx context.Context, id string, client fosite.Client) error
	}); ok {
		if err := storage.UpdateClient(ctx, id, client); err != nil {
			log.Printf("❌ CustomStorage.UpdateClient: failed to update client %s in storage: %v", id, err)
			return err
		}
	} else {
		log.Printf("⚠️ CustomStorage.UpdateClient: underlying storage does not support UpdateClient")
	}

	log.Printf("✅ CustomStorage.UpdateClient: client %s updated", id)
	return nil
}

func (s *CustomStorage) DeleteClient(ctx context.Context, id string) error {
	log.Printf("🔍 CustomStorage.DeleteClient: deleting client %s from map and storage", id)

	// Delete from memory map
	delete(s.Clients, id)

	// Also delete from underlying storage
	if storage, ok := s.Storage.(interface {
		DeleteClient(ctx context.Context, id string) error
	}); ok {
		if err := storage.DeleteClient(ctx, id); err != nil {
			log.Printf("❌ CustomStorage.DeleteClient: failed to delete client %s from storage: %v", id, err)
			return err
		}
	} else {
		log.Printf("⚠️ CustomStorage.DeleteClient: underlying storage does not support DeleteClient")
	}

	log.Printf("✅ CustomStorage.DeleteClient: client %s deleted", id)
	return nil
}

func (s *CustomStorage) CreateUser(ctx context.Context, id string, user *storage.MemoryUserRelation) error {
	s.Users[id] = *user
	return nil
}

func (s *CustomStorage) UpdateUser(ctx context.Context, id string, user *storage.MemoryUserRelation) error {
	s.Users[id] = *user
	return nil
}

func (s *CustomStorage) DeleteUser(ctx context.Context, id string) error {
	delete(s.Users, id)
	return nil
}

// Delegate other store.Storage methods to underlying store
func (s *CustomStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.Storage.(interface {
		CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error
	}).CreateAccessTokenSession(ctx, signature, request)
}

func (s *CustomStorage) CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, request fosite.Requester) error {
	return s.Storage.(interface {
		CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, request fosite.Requester) error
	}).CreateRefreshTokenSession(ctx, signature, accessTokenSignature, request)
}

func (s *CustomStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.Storage.(interface {
		CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error
	}).CreateAuthorizeCodeSession(ctx, code, request)
}

func (s *CustomStorage) CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.Storage.(interface {
		CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error
	}).CreatePKCERequestSession(ctx, code, request)
}

func (s *CustomStorage) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.DeviceRequester, error) {
	return s.Storage.(interface {
		GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.DeviceRequester, error)
	}).GetDeviceCodeSession(ctx, deviceCode, session)
}

func (s *CustomStorage) CreateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	return s.Storage.(interface {
		CreateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error
	}).CreateDeviceCodeSession(ctx, deviceCode, request)
}

func (s *CustomStorage) UpdateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	return s.Storage.(interface {
		UpdateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error
	}).UpdateDeviceCodeSession(ctx, deviceCode, request)
}

func (s *CustomStorage) InvalidateDeviceCodeSession(ctx context.Context, signature string) error {
	return s.Storage.(interface {
		InvalidateDeviceCodeSession(ctx context.Context, signature string) error
	}).InvalidateDeviceCodeSession(ctx, signature)
}

// Authenticate implements ResourceOwnerPasswordCredentialsGrantStorage

func (s *CustomStorage) GetPendingDeviceAuths(ctx context.Context) (map[string]fosite.Requester, error) {
	return s.Storage.(interface {
		GetPendingDeviceAuths(ctx context.Context) (map[string]fosite.Requester, error)
	}).GetPendingDeviceAuths(ctx)
}

func (s *CustomStorage) CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.DeviceRequester) error {
	return s.Storage.(interface {
		CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.DeviceRequester) error
	}).CreateDeviceAuthSession(ctx, deviceCodeSignature, userCodeSignature, request)
}

// Authenticate implements ResourceOwnerPasswordCredentialsGrantStorage
func (s *CustomStorage) Authenticate(ctx context.Context, name string, secret string) (string, error) {
	// Find user by username
	for id, user := range s.Users {
		if user.Username == name {
			// Check password
			if user.Password == secret {
				// Return the user ID as subject
				return id, nil
			}
			break
		}
	}
	return "", fosite.ErrInvalidGrant
}

func (s *CustomStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.Storage.(interface {
		GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	}).GetAccessTokenSession(ctx, signature, session)
}

func (s *CustomStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.Storage.(interface {
		DeleteAccessTokenSession(ctx context.Context, signature string) error
	}).DeleteAccessTokenSession(ctx, signature)
}

func (s *CustomStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.Storage.(interface {
		GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	}).GetRefreshTokenSession(ctx, signature, session)
}

func (s *CustomStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.Storage.(interface {
		DeleteRefreshTokenSession(ctx context.Context, signature string) error
	}).DeleteRefreshTokenSession(ctx, signature)
}

func (s *CustomStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return s.Storage.(interface {
		RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error
	}).RotateRefreshToken(ctx, requestID, refreshTokenSignature)
}

func (s *CustomStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.Storage.(interface {
		RevokeAccessToken(ctx context.Context, requestID string) error
	}).RevokeAccessToken(ctx, requestID)
}

func (s *CustomStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.Storage.(interface {
		RevokeRefreshToken(ctx context.Context, requestID string) error
	}).RevokeRefreshToken(ctx, requestID)
}

func (s *CustomStorage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return s.Storage.(interface {
		GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error)
	}).GetAuthorizeCodeSession(ctx, code, session)
}

func (s *CustomStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.Storage.(interface {
		InvalidateAuthorizeCodeSession(ctx context.Context, code string) error
	}).InvalidateAuthorizeCodeSession(ctx, code)
}

func (s *CustomStorage) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return s.Storage.(interface {
		GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error)
	}).GetPKCERequestSession(ctx, code, session)
}

func (s *CustomStorage) DeletePKCERequestSession(ctx context.Context, code string) error {
	return s.Storage.(interface {
		DeletePKCERequestSession(ctx context.Context, code string) error
	}).DeletePKCERequestSession(ctx, code)
}

func (s *CustomStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.ClientAssertionJWTValid(ctx, jti)
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.ClientAssertionJWTValid(ctx, jti)
	}
	if store, ok := s.Storage.(*storage.MemoryStore); ok {
		return store.ClientAssertionJWTValid(ctx, jti)
	}
	return fosite.ErrInvalidRequest // Fallback
}

func (s *CustomStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.SetClientAssertionJWT(ctx, jti, exp)
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.SetClientAssertionJWT(ctx, jti, exp)
	}
	if store, ok := s.Storage.(*storage.MemoryStore); ok {
		return store.SetClientAssertionJWT(ctx, jti, exp)
	}
	return nil // Fallback
}

func (s *CustomStorage) GetClientCount() (int, error) {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.GetClientCount()
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.GetClientCount()
	}
	return len(s.Clients), nil // Fallback
}

func (s *CustomStorage) GetUserCount() (int, error) {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.GetUserCount()
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.GetUserCount()
	}
	return len(s.Users), nil // Fallback
}

func (s *CustomStorage) GetAccessTokenCount() (int, error) {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.GetAccessTokenCount()
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.GetAccessTokenCount()
	}
	return 0, nil // Fallback
}

func (s *CustomStorage) GetRefreshTokenCount() (int, error) {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.GetRefreshTokenCount()
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.GetRefreshTokenCount()
	}
	return 0, nil // Fallback
}

// GetClient returns a client but makes it appear public to skip Fosite's authentication
func (s *CustomStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	log.Printf("🔍 CustomStorage.GetClient: looking for client %s (total clients in map: %d)", id, len(s.Clients))

	client, exists := s.Clients[id]
	if !exists {
		log.Printf("⚠️ CustomStorage.GetClient: client %s not found in map, checking underlying storage", id)

		// Check underlying storage for dynamically registered clients
		if storage, ok := s.Storage.(interface {
			GetClient(ctx context.Context, id string) (fosite.Client, error)
		}); ok {
			underlyingClient, err := storage.GetClient(ctx, id)
			if err == nil {
				log.Printf("✅ CustomStorage.GetClient: found client %s in underlying storage", id)
				client = underlyingClient
				exists = true
			} else {
				log.Printf("❌ CustomStorage.GetClient: client %s not found in underlying storage either: %v", id, err)
			}
		} else {
			// Check if it's a MemoryStoreWrapper and access the embedded MemoryStore directly
			if memoryWrapper, ok := s.Storage.(*MemoryStoreWrapper); ok {
				if memClient, exists := memoryWrapper.MemoryStore.Clients[id]; exists {
					log.Printf("✅ CustomStorage.GetClient: found client %s in MemoryStore", id)
					client = memClient
					exists = true
				} else {
					log.Printf("❌ CustomStorage.GetClient: client %s not found in MemoryStore either", id)
				}
			} else {
				log.Printf("⚠️ CustomStorage.GetClient: underlying storage does not support GetClient and is not MemoryStoreWrapper")
			}
		}
	}

	if !exists {
		log.Printf("❌ CustomStorage.GetClient: client %s not found anywhere", id)
		return nil, fosite.ErrInvalidClient
	}

	log.Printf("✅ CustomStorage.GetClient: found client %s (type: %T, Public: %v)", id, client, client.IsPublic())

	// For public clients (token_endpoint_auth_method = "none"), modify the client to be public
	if defaultClient, ok := client.(*fosite.DefaultClient); ok {
		// Check if this client should be public based on token_endpoint_auth_method
		// Public clients have token_endpoint_auth_method = "none"
		authMethod := "client_secret_basic" // default
		if defaultClient.Public {
			authMethod = "none"
		}

		// If client is configured as public or has no secret, make it public
		if defaultClient.Public || (defaultClient.GetHashedSecret() == nil || len(defaultClient.GetHashedSecret()) == 0) {
			log.Printf("🔄 CustomStorage.GetClient: making client %s public (auth_method: %s)", id, authMethod)

			// Create a copy of the client and set Public = true
			publicClient := &fosite.DefaultClient{
				ID:            defaultClient.ID,
				Secret:        defaultClient.Secret,
				RedirectURIs:  defaultClient.RedirectURIs,
				GrantTypes:    defaultClient.GrantTypes,
				ResponseTypes: defaultClient.ResponseTypes,
				Scopes:        defaultClient.Scopes,
				Audience:      defaultClient.Audience,
				Public:        true, // Make it public
			}
			return publicClient, nil
		}
	}

	log.Printf("✅ CustomStorage.GetClient: returning client %s as-is", id)
	return client, nil
}

// GetUser returns a user from the custom storage
func (s *CustomStorage) GetUser(ctx context.Context, id string) (*storage.MemoryUserRelation, error) {
	user, exists := s.Users[id]
	if !exists {
		// Try to get from underlying storage if it supports it
		if memoryStore, ok := s.Storage.(*storage.MemoryStore); ok {
			user, exists := memoryStore.Users[id]
			if exists {
				return &user, nil
			}
		}
		if sqliteStore, ok := s.Storage.(*SQLiteStore); ok {
			return sqliteStore.GetUser(ctx, id)
		}
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

// Implement the encrypted storage methods by delegating to underlying store
func (s *CustomStorage) StoreClientSecret(ctx context.Context, clientID string, encryptedSecret string) error {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.StoreClientSecret(ctx, clientID, encryptedSecret)
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.StoreClientSecret(ctx, clientID, encryptedSecret)
	}
	return fmt.Errorf("underlying store does not support encrypted secret storage")
}

func (s *CustomStorage) GetClientSecret(ctx context.Context, clientID string) (string, error) {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.GetClientSecret(ctx, clientID)
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.GetClientSecret(ctx, clientID)
	}
	return "", fmt.Errorf("underlying store does not support encrypted secret storage")
}

func (s *CustomStorage) StoreAttestationConfig(ctx context.Context, clientID string, config *config.ClientAttestationConfig) error {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.StoreAttestationConfig(ctx, clientID, config)
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.StoreAttestationConfig(ctx, clientID, config)
	}
	return fmt.Errorf("underlying store does not support attestation config storage")
}

func (s *CustomStorage) GetAttestationConfig(ctx context.Context, clientID string) (*config.ClientAttestationConfig, error) {
	if store, ok := s.Storage.(*MemoryStoreWrapper); ok {
		return store.GetAttestationConfig(ctx, clientID)
	}
	if store, ok := s.Storage.(*SQLiteStore); ok {
		return store.GetAttestationConfig(ctx, clientID)
	}
	return nil, fmt.Errorf("underlying store does not support attestation config storage")
}
