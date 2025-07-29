package store

import (
	"bytes"
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"oauth2-server/internal/models"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
)

// ClientStore manages OAuth2 clients
type ClientStore struct {
	clients map[string]fosite.Client
	mutex   sync.RWMutex
}

// NewClientStore creates a new client store
func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: make(map[string]fosite.Client),
	}
}

// Client represents an OAuth2 client
type Client struct {
	ID                      string
	Secret                  []byte
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	Audience                []string
	Public                  bool
	Name                    string
	Description             string
	TokenEndpointAuthMethod string
	EnabledFlows            []string
}

// GetID returns the client ID
func (c *Client) GetID() string {
	return c.ID
}

// GetHashedSecret returns the hashed client secret
func (c *Client) GetHashedSecret() []byte {
	return c.Secret
}

// GetSecret returns the client secret as string (helper method)
func (c *Client) GetSecret() string {
	return string(c.Secret)
}

// GetRedirectURIs returns the client's redirect URIs
func (c *Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetGrantTypes returns the client's allowed grant types
func (c *Client) GetGrantTypes() fosite.Arguments {
	return fosite.Arguments(c.GrantTypes)
}

// GetResponseTypes returns the client's allowed response types
func (c *Client) GetResponseTypes() fosite.Arguments {
	return fosite.Arguments(c.ResponseTypes)
}

// GetScopes returns the client's allowed scopes
func (c *Client) GetScopes() fosite.Arguments {
	return fosite.Arguments(c.Scopes)
}

// IsPublic returns whether the client is public
func (c *Client) IsPublic() bool {
	return c.Public
}

// GetAudience returns the client's audience
func (c *Client) GetAudience() fosite.Arguments {
	return fosite.Arguments(c.Audience)
}

// ValidateRedirectURI validates a redirect URI against this client's registered URIs
func (c *Client) ValidateRedirectURI(requestedURI string) bool {
	return utils.ValidateClientRedirectURI(requestedURI, c.RedirectURIs)
}

// CreateDefaultClient creates a default client from ClientInfo
func CreateDefaultClient(info models.ClientInfo) *Client {
	return &Client{
		ID:            info.ID,
		Secret:        []byte(info.Secret),
		RedirectURIs:  info.RedirectURIs,
		GrantTypes:    info.GrantTypes,
		ResponseTypes: info.ResponseTypes,
		Scopes:        info.Scopes,
		Audience:      info.Audience,
		Public:        false, // You can add this field to models.ClientInfo if needed
		Name:          info.Name,
	}
}

// StoreClient stores a client
func (s *ClientStore) StoreClient(client fosite.Client) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.clients[client.GetID()] = client
	return nil
}

// GetClient retrieves a client by ID
func (s *ClientStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	client, exists := s.clients[id]
	if !exists {
		return nil, errors.New("client not found")
	}

	return client, nil
}

// ValidateClientCredentials validates client credentials
func (s *ClientStore) ValidateClientCredentials(clientID, clientSecret string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return errors.New("client not found")
	}

	// Type assert to our Client struct to access Public field
	if ourClient, ok := client.(*Client); ok {
		// For public clients, no secret is required
		if ourClient.Public {
			return nil
		}
	}

	// Compare client secret (convert byte slice to string for comparison)
	if !bytes.Equal(client.GetHashedSecret(), []byte(clientSecret)) {
		return errors.New("invalid client secret")
	}

	return nil
}

// DeleteClient removes a client
func (s *ClientStore) DeleteClient(clientID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		return errors.New("client not found")
	}

	delete(s.clients, clientID)
	return nil
}

// ListClients returns all clients
func (s *ClientStore) ListClients() []fosite.Client {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	clients := make([]fosite.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	return clients
}

// UpdateClient updates an existing client
func (s *ClientStore) UpdateClient(info models.ClientInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.clients[info.ID]; !exists {
		return errors.New("client not found")
	}

	updatedClient := CreateDefaultClient(info)
	s.clients[info.ID] = updatedClient

	return nil
}

// ClientExists checks if a client exists
func (s *ClientStore) ClientExists(clientID string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	_, exists := s.clients[clientID]
	return exists
}

// LoadDefaultClients loads default clients into the store
func (s *ClientStore) LoadDefaultClients(frontendClient, backendClient models.ClientInfo) {
	frontendClient.CreatedAt = time.Now()
	frontendClient.UpdatedAt = time.Now()
	backendClient.CreatedAt = time.Now()
	backendClient.UpdatedAt = time.Now()

	s.StoreClient(CreateDefaultClient(frontendClient))
	s.StoreClient(CreateDefaultClient(backendClient))
}

// LoadClientsFromConfig loads clients from configuration into the store
func (cs *ClientStore) LoadClientsFromConfig(clients []config.ClientConfig) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	for _, clientConfig := range clients {
		// Hash the client secret if it exists
		var hashedSecret []byte
		if clientConfig.Secret != "" {
			// In production, use proper password hashing (bcrypt, argon2, etc.)
			hashedSecret = []byte(clientConfig.Secret) // Simplified for now
		}

		client := &Client{
			ID:                      clientConfig.ID,
			Secret:                  hashedSecret,
			Name:                    clientConfig.Name,
			Description:             clientConfig.Description,
			RedirectURIs:            clientConfig.RedirectURIs,
			GrantTypes:              clientConfig.GrantTypes,
			ResponseTypes:           clientConfig.ResponseTypes,
			Scopes:                  clientConfig.Scopes,
			Audience:                clientConfig.Audience,
			TokenEndpointAuthMethod: clientConfig.TokenEndpointAuthMethod,
			Public:                  clientConfig.Public,
			EnabledFlows:            clientConfig.EnabledFlows,
		}

		cs.clients[clientConfig.ID] = client
		log.Printf("✅ Loaded client from config: %s (%s) Redirect URIs: %v", client.ID, client.Name, client.RedirectURIs)
	}

	log.Printf("📦 Loaded %d clients from configuration", len(clients))
	return nil
}

// GetStats returns statistics about the client store
func (s *ClientStore) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total": len(s.clients),
		// Add more stats as needed
	}
}
