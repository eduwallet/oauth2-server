package models

import (
	"errors"
	"time"
)

// ClientInfo represents client information
type ClientInfo struct {
	ID            string    `json:"client_id"`
	Secret        string    `json:"client_secret,omitempty"`
	Name          string    `json:"name,omitempty"`
	Description   string    `json:"description,omitempty"`
	RedirectURIs  []string  `json:"redirect_uris"`
	GrantTypes    []string  `json:"grant_types"`
	ResponseTypes []string  `json:"response_types"`
	Scopes        []string  `json:"scopes"`
	Audience      []string  `json:"audience,omitempty"`
	ClientName    string    `json:"client_name,omitempty"`
	ClientURI     string    `json:"client_uri,omitempty"`
	LogoURI       string    `json:"logo_uri,omitempty"`
	ContactEmails []string  `json:"contacts,omitempty"`
	TOSUri        string    `json:"tos_uri,omitempty"`
	PolicyURI     string    `json:"policy_uri,omitempty"`
	JWKSURI       string    `json:"jwks_uri,omitempty"`
	JWKSValue     string    `json:"jwks,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ClientRegistrationRequest represents a dynamic client registration request
type ClientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	Audience                []string `json:"audience,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	Jwks                    string   `json:"jwks,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	SoftwareStatement       string   `json:"software_statement,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	SectorIdentifierURI     string   `json:"sector_identifier_uri,omitempty"`
	SubjectType             string   `json:"subject_type,omitempty"`
}

// ClientRegistrationResponse represents the response to a client registration request
type ClientRegistrationResponse struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64     `json:"client_secret_expires_at"`
	Audience                []string  `json:"audience,omitempty"`
	RegistrationAccessToken string    `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string    `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string  `json:"grant_types,omitempty"`
	ResponseTypes           []string  `json:"response_types,omitempty"`
	ClientName              string    `json:"client_name,omitempty"`
	ClientURI               string    `json:"client_uri,omitempty"`
	LogoURI                 string    `json:"logo_uri,omitempty"`
	Scope                   string    `json:"scope,omitempty"`
	Contacts                []string  `json:"contacts,omitempty"`
	TosURI                  string    `json:"tos_uri,omitempty"`
	PolicyURI               string    `json:"policy_uri,omitempty"`
	JwksURI                 string    `json:"jwks_uri,omitempty"`
	Jwks                    string    `json:"jwks,omitempty"`
	SoftwareID              string    `json:"software_id,omitempty"`
	SoftwareVersion         string    `json:"software_version,omitempty"`
	ApplicationType         string    `json:"application_type,omitempty"`
	SectorIdentifierURI     string    `json:"sector_identifier_uri,omitempty"`
	SubjectType             string    `json:"subject_type,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// RegisteredClient represents a registered OAuth2 client
type RegisteredClient struct {
	ID                        string    `json:"client_id"`
	Secret                    string    `json:"client_secret,omitempty"`
	SecretExpiresAt           int64     `json:"client_secret_expires_at"`
	RegistrationAccessToken   string    `json:"registration_access_token,omitempty"`
	RedirectURIs              []string  `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod   string    `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                []string  `json:"grant_types,omitempty"`
	ResponseTypes             []string  `json:"response_types,omitempty"`
	Name                      string    `json:"client_name,omitempty"`
	URI                       string    `json:"client_uri,omitempty"`
	LogoURI                   string    `json:"logo_uri,omitempty"`
	Scope                     string    `json:"scope,omitempty"`
	Contacts                  []string  `json:"contacts,omitempty"`
	TosURI                    string    `json:"tos_uri,omitempty"`
	PolicyURI                 string    `json:"policy_uri,omitempty"`
	JwksURI                   string    `json:"jwks_uri,omitempty"`
	Jwks                      string    `json:"jwks,omitempty"`
	SoftwareID                string    `json:"software_id,omitempty"`
	SoftwareVersion           string    `json:"software_version,omitempty"`
	ApplicationType           string    `json:"application_type,omitempty"`
	SectorIdentifierURI       string    `json:"sector_identifier_uri,omitempty"`
	SubjectType               string    `json:"subject_type,omitempty"`
	RequestObjectSigningAlg   string    `json:"request_object_signing_alg,omitempty"`
	UserinfoSignedResponseAlg string    `json:"userinfo_signed_response_alg,omitempty"`
	IDTokenSignedResponseAlg  string    `json:"id_token_signed_response_alg,omitempty"`
	DefaultMaxAge             int       `json:"default_max_age,omitempty"`
	RequireAuthTime           bool      `json:"require_auth_time,omitempty"`
	DefaultACRValues          []string  `json:"default_acr_values,omitempty"`
	InitiateLoginURI          string    `json:"initiate_login_uri,omitempty"`
	RequestURIs               []string  `json:"request_uris,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// Common validation errors
var (
	ErrInvalidClientID     = errors.New("invalid client ID")
	ErrInvalidClientSecret = errors.New("invalid client secret")
	ErrInvalidRedirectURI  = errors.New("invalid redirect URI")
	ErrInvalidGrantType    = errors.New("invalid grant type")
	ErrInvalidScope        = errors.New("invalid scope")
	ErrInvalidUsername     = errors.New("invalid username")
	ErrInvalidEmail        = errors.New("invalid email")
)

// ValidateClient validates client information
func (c *ClientInfo) ValidateClient() error {
	if c.ID == "" {
		return ErrInvalidClientID
	}
	if len(c.RedirectURIs) == 0 && !c.HasGrantType("client_credentials") {
		return ErrInvalidRedirectURI
	}
	return nil
}

// HasGrantType checks if the client has a specific grant type
func (c *ClientInfo) HasGrantType(grantType string) bool {
	for _, gt := range c.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// HasScope checks if the client has a specific scope
func (c *ClientInfo) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAudience checks if the client has a specific audience
func (c *ClientInfo) HasAudience(audience string) bool {
	for _, aud := range c.Audience {
		if aud == audience {
			return true
		}
	}
	return false
}
