package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/ory/fosite"
	"oauth2-server/pkg/config"
)

// SimpleClientManager implements fosite.ClientManager
type SimpleClientManager struct {
	clients map[string]*SimpleClient
	mutex   sync.RWMutex
}

// NewSimpleClientManager creates a new simple client manager
func NewSimpleClientManager() *SimpleClientManager {
	return &SimpleClientManager{
		clients: make(map[string]*SimpleClient),
	}
}

// GetClient implements fosite.ClientManager
func (m *SimpleClientManager) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if client, found := m.clients[id]; found {
		return client, nil
	}

	return nil, fosite.ErrNotFound
}

// RegisterClient dynamically registers a new client
func (m *SimpleClientManager) RegisterClient(req ClientRegistrationRequest) (*SimpleClient, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Generate client ID and secret
	clientID := generateClientID()
	clientSecret := generateClientSecret()

	// Set defaults if not provided
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	client := &SimpleClient{
		ID:                      clientID,
		Secret:                  clientSecret,
		Name:                    req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scopes:                  req.Scopes,
		Audience:                req.Audience,
		Public:                  req.ClientType == "public",
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
	}

	m.clients[clientID] = client
	return client, nil
}

// LoadClientsFromConfig loads clients from configuration - FIXED METHOD NAME AND TYPE
func (m *SimpleClientManager) LoadClientsFromConfig(configClients []config.ClientConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, config := range configClients {
		client := &SimpleClient{
			ID:                      config.ID,
			Secret:                  config.Secret,
			Name:                    config.Name,
			RedirectURIs:            config.RedirectURIs,
			GrantTypes:              config.GrantTypes,
			ResponseTypes:           config.ResponseTypes,
			Scopes:                  config.Scopes,
			Audience:                config.Audience,
			Public:                  config.Public,
			TokenEndpointAuthMethod: config.TokenEndpointAuthMethod,
		}

		m.clients[config.ID] = client
		fmt.Printf("✅ Loaded client from config: %s (%s)\n", client.ID, client.Name)
	}

	return nil
}

// ListClients returns a list of all registered clients (for stats)
func (m *SimpleClientManager) ListClients() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	clients := make([]string, 0, len(m.clients))
	for id := range m.clients {
		clients = append(clients, id)
	}
	return clients
}

// GetClientCount returns the number of registered clients
func (m *SimpleClientManager) GetClientCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.clients)
}

// Helper types
type ClientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	ClientType              string   `json:"client_type,omitempty"` // "public" or "confidential"
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	Audience                []string `json:"audience,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// Utility functions
func generateClientID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return "client_" + hex.EncodeToString(bytes)
}

func generateClientSecret() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
