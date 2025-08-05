package storage

import (
	"context"
	"fmt"
	"sync"

	"oauth2-server/internal/config"
)

// CustomStorage provides storage for OAuth2 data
type CustomStorage struct {
	clients map[string]*config.ClientConfig
	users   map[string]*config.UserConfig
	mu      sync.RWMutex
}

// NewCustomStorage creates a new custom storage instance
func NewCustomStorage() *CustomStorage {
	return &CustomStorage{
		clients: make(map[string]*config.ClientConfig),
		users:   make(map[string]*config.UserConfig),
	}
}

// LoadClientsFromConfig loads clients from configuration
func (s *CustomStorage) LoadClientsFromConfig(clients []config.ClientConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, clientConfig := range clients {
		s.clients[clientConfig.ID] = &clientConfig
	}
}

// LoadUsersFromConfig loads users from configuration
func (s *CustomStorage) LoadUsersFromConfig(users []config.UserConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, user := range users {
		s.users[user.Username] = &user
	}
}

// GetClient returns a client by ID
func (s *CustomStorage) GetClient(ctx context.Context, id string) (*config.ClientConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if client, found := s.clients[id]; found {
		return client, nil
	}
	return nil, fmt.Errorf("client not found")
}

// AuthenticateUser authenticates a user by username and password
func (s *CustomStorage) AuthenticateUser(username, password string) (*config.UserConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, found := s.users[username]
	if !found {
		return nil, fmt.Errorf("user not found")
	}

	if !user.Enabled {
		return nil, fmt.Errorf("user is disabled")
	}

	// In a real implementation, you would hash and compare passwords
	if user.Password != password {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

// TODO: When enabling full Fosite integration, add these methods back:
// - ValidateSubjectToken for RFC 8693 support
// - ValidateActorToken for RFC 8693 support
// - StoreTokenExchange for RFC 8693 support
// These will be implemented when the fosite replace directive is uncommented
