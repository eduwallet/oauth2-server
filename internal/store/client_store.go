package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"oauth2-server/internal/models"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/go-jose/go-jose/v3"
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
	log.Printf("[DEBUG] ClientStore.StoreClient called with clientID=%s", client.GetID())
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.clients[client.GetID()] = client
	return nil
}

// GetClient retrieves a client by ID
func (s *ClientStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	log.Printf("[DEBUG] ClientStore.GetClient called with id=%s", id)
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	log.Printf("XXXX Getting client with ID:", id)

	client, exists := s.clients[id]
	if !exists {
		return nil, fosite.ErrNotFound
	}
	log.Printf("XXXX Getting client with ID:", id, "found:", client.GetID())
	return client, nil
}

// ValidateClientCredentials validates client credentials
func (s *ClientStore) ValidateClientCredentials(clientID, clientSecret string) error {
	log.Printf("[DEBUG] ClientStore.ValidateClientCredentials called with clientID=%s", clientID)
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	fmt.Println("XXXX Validating client credentials for client:", clientID, "secret:", clientSecret)

	client, exists := s.clients[clientID]
	if !exists {
		return fosite.ErrNotFound
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

	log.Printf("✅ Client credentials validated for client: %s", clientID)

	return nil
}

// DeleteClient removes a client
func (s *ClientStore) DeleteClient(clientID string) error {
	log.Printf("[DEBUG] ClientStore.DeleteClient called with clientID=%s", clientID)
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		return fosite.ErrNotFound
	}

	delete(s.clients, clientID)
	return nil
}

// ListClients returns all clients
func (s *ClientStore) ListClients() []fosite.Client {
	log.Printf("[DEBUG] ClientStore.ListClients called")
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	clients := make([]fosite.Client, 0, len(s.clients))
	for _, client := range s.clients {
		fmt.Println("Client ID:", client.GetID())
		if ourClient, ok := client.(*Client); ok {
			fmt.Println("Client Secret:", ourClient.GetSecret())
			fmt.Println("Client Redirect URIs:", ourClient.GetRedirectURIs())
			fmt.Println("Client Grant Types:", ourClient.GetGrantTypes())
			fmt.Printf("Client %s response_types: %#v\n", ourClient.GetID(), ourClient.GetResponseTypes())
			fmt.Println("Client Scopes:", ourClient.GetScopes())
			fmt.Println("Client Audience:", ourClient.GetAudience())
			fmt.Println("Client Public:", ourClient.IsPublic())
			fmt.Println("Client Enabled Flows:", ourClient.EnabledFlows)
		}
		clients = append(clients, client)
	}

	return clients
}

// UpdateClient updates an existing client
func (s *ClientStore) UpdateClient(info models.ClientInfo) error {
	log.Printf("[DEBUG] ClientStore.UpdateClient called with clientID=%s", info.ID)
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.clients[info.ID]; !exists {
		return fosite.ErrNotFound
	}

	updatedClient := CreateDefaultClient(info)
	s.clients[info.ID] = updatedClient

	return nil
}

// ClientExists checks if a client exists
func (s *ClientStore) ClientExists(clientID string) bool {
	log.Printf("[DEBUG] ClientStore.ClientExists called with clientID=%s", clientID)
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	_, exists := s.clients[clientID]
	return exists
}

// LoadClientsFromConfig loads clients from configuration into the store
func (cs *ClientStore) LoadClientsFromConfig(clients []config.ClientConfig) error {
	log.Printf("[DEBUG] ClientStore.LoadClientsFromConfig called with %d clients", len(clients))
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
	log.Printf("[DEBUG] ClientStore.GetStats called")
	return map[string]interface{}{
		"total": len(s.clients),
		// Add more stats as needed
	}
}

// ClientAssertionJWTValid is required by fosite.Storage for JWT profile grant (noop for most setups)
func (s *ClientStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	log.Printf("[DEBUG] ClientStore.ClientAssertionJWTValid called with jti=%s", jti)
	// If you do not support JWT client assertion, return fosite.ErrNotFound
	return fosite.ErrNotFound
}

// SetClientAssertionJWT is required by fosite.Storage for JWT profile grant (noop for most setups)
func (s *ClientStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	log.Printf("[DEBUG] ClientStore.SetClientAssertionJWT called with jti=%s, exp=%v", jti, exp)
	// If you do not support JWT client assertion, do nothing
	return nil
}

// GetPublicKey is required by RFC7523KeyStorage for JWT assertion grant (RFC 7523). If you do not support JWT assertion, return fosite.ErrNotFound.
func (s *ClientStore) GetPublicKey(ctx context.Context, issuer, subject string, keyID string) (*jose.JSONWebKey, error) {
	log.Printf("[DEBUG] ClientStore.GetPublicKey called with issuer=%s, subject=%s, keyID=%s", issuer, subject, keyID)
	return nil, fosite.ErrNotFound
}

// GetPublicKeyScopes is required by RFC7523KeyStorage for JWT assertion grant (RFC 7523). If you do not support JWT assertion, return fosite.ErrNotFound.
func (s *ClientStore) GetPublicKeyScopes(ctx context.Context, issuer, subject, keyID string) ([]string, error) {
	log.Printf("[DEBUG] ClientStore.GetPublicKeyScopes called with issuer=%s, subject=%s, keyID=%s", issuer, subject, keyID)
	// If you do not support JWT assertion, return fosite.ErrNotFound
	return nil, fosite.ErrNotFound
}

func (s *ClientStore) Authenticate(ctx context.Context, name string, secret string) (string, error) {
	log.Printf("[DEBUG] ClientStore.Authenticate called with name=%s, secret=****", name)
	client, err := s.GetClient(ctx, name)
	if err != nil {
		return "", err
	}
	if !client.IsPublic() && string(client.GetHashedSecret()) == secret {
		return client.GetID(), nil
	}
	return "", fosite.ErrNotFound
}

func (s *ClientStore) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	log.Printf("[DEBUG] ClientStore.SetTokenLifespans called with clientID=%s, lifespans=%+v", clientID, lifespans)
	return nil
}
func (s *ClientStore) GetPublicKeys(ctx context.Context, issuer, subject string) (*jose.JSONWebKeySet, error) {
	log.Printf("[DEBUG] ClientStore.GetPublicKeys called with issuer=%s, subject=%s", issuer, subject)
	return nil, fosite.ErrNotFound
}