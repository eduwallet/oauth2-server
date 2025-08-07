package store

import (
    "github.com/ory/fosite"
)

// SimpleClient implements fosite.Client interface
type SimpleClient struct {
    ID                      string
    Secret                  string // Store as plaintext, fosite handles hashing
    RedirectURIs            []string
    GrantTypes              []string
    ResponseTypes           []string
    Scopes                  []string
    Audience                []string
    Public                  bool
    Name                    string
    TokenEndpointAuthMethod string
}

// GetID implements fosite.Client
func (c *SimpleClient) GetID() string {
    return c.ID
}

// GetHashedSecret implements fosite.Client
func (c *SimpleClient) GetHashedSecret() []byte {
    return []byte(c.Secret) // Fosite will handle proper hashing
}

// GetRedirectURIs implements fosite.Client
func (c *SimpleClient) GetRedirectURIs() []string {
    return c.RedirectURIs
}

// GetGrantTypes implements fosite.Client
func (c *SimpleClient) GetGrantTypes() fosite.Arguments {
    return fosite.Arguments(c.GrantTypes)
}

// GetResponseTypes implements fosite.Client
func (c *SimpleClient) GetResponseTypes() fosite.Arguments {
    return fosite.Arguments(c.ResponseTypes)
}

// GetScopes implements fosite.Client
func (c *SimpleClient) GetScopes() fosite.Arguments {
    return fosite.Arguments(c.Scopes)
}

// IsPublic implements fosite.Client
func (c *SimpleClient) IsPublic() bool {
    return c.Public
}

// GetAudience implements fosite.Client
func (c *SimpleClient) GetAudience() fosite.Arguments {
    return fosite.Arguments(c.Audience)
}