package storage

import (
	"time"
)

// Storage interface defines the methods for persisting OAuth2 data
type Storage interface {
	// Authorization codes
	StoreAuthCode(code *AuthCodeState) error
	GetAuthCode(code string) (*AuthCodeState, error)
	DeleteAuthCode(code string) error

	// Device codes
	StoreDeviceCode(deviceCode *DeviceCodeState) error
	GetDeviceCode(deviceCode string) (*DeviceCodeState, error)
	GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, error)
	UpdateDeviceCode(deviceCode *DeviceCodeState) error
	DeleteDeviceCode(deviceCode string) error

	// Dynamic clients
	StoreDynamicClient(client *DynamicClient) error
	GetDynamicClient(clientID string) (*DynamicClient, error)
	UpdateDynamicClient(client *DynamicClient) error
	DeleteDynamicClient(clientID string) error

	// Registration tokens
	StoreRegistrationToken(token *RegistrationToken) error
	GetRegistrationToken(token string) (*RegistrationToken, error)
	DeleteRegistrationToken(token string) error

	// OAuth2 Tokens (Access, Refresh, ID tokens)
	StoreToken(token *TokenState) error
	GetToken(token string) (*TokenState, error)
	UpdateToken(token *TokenState) error
	DeleteToken(token string) error

	// Sessions
	StoreSession(session *SessionState) error
	GetSession(sessionID string) (*SessionState, error)
	DeleteSession(sessionID string) error

	// Cleanup expired entries
	CleanupExpired() error

	// Close the storage
	Close() error
}

// AuthCodeState represents an OAuth2 authorization code state
type AuthCodeState struct {
	Code                string                 `json:"code"`
	ClientID            string                 `json:"client_id"`
	UserID              string                 `json:"user_id"`
	RedirectURI         string                 `json:"redirect_uri"`
	ResponseType        string                 `json:"response_type"` // Added missing field
	Scopes              []string               `json:"scopes"`
	State               string                 `json:"state"`
	CodeChallenge       string                 `json:"code_challenge,omitempty"`
	CodeChallengeMethod string                 `json:"code_challenge_method,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	ExpiresAt           time.Time              `json:"expires_at"`
	Extra               map[string]interface{} `json:"extra,omitempty"`
}

// DeviceCodeResponse represents the response for device authorization
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceCodeState represents the internal state of a device authorization
type DeviceCodeState struct {
	DeviceCode  string    `json:"device_code"`
	UserCode    string    `json:"user_code"`
	ClientID    string    `json:"client_id"`
	UserID      string    `json:"user_id,omitempty"`
	Scopes      []string  `json:"scopes"`
	ExpiresIn   int       `json:"expires_in"`
	ExpiresAt   time.Time `json:"expires_at"`
	Interval    int       `json:"interval"`
	CreatedAt   time.Time `json:"created_at"`
	Authorized  bool      `json:"authorized"`
	AccessToken string    `json:"access_token,omitempty"`
}

// DynamicClient represents a dynamically registered OAuth2 client
type DynamicClient struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty"`
	ClientName              string    `json:"client_name,omitempty"`
	Description             string    `json:"description,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris,omitempty"`
	GrantTypes              []string  `json:"grant_types,omitempty"`
	ResponseTypes           []string  `json:"response_types,omitempty"`
	Scopes                  []string  `json:"scopes,omitempty"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	Public                  bool      `json:"public"`
	AllowedAudiences        []string  `json:"allowed_audiences,omitempty"`
	AllowTokenExchange      bool      `json:"allow_token_exchange"`
	AllowedOrigins          []string  `json:"allowed_origins,omitempty"`
	SoftwareID              string    `json:"software_id,omitempty"`
	SoftwareVersion         string    `json:"software_version,omitempty"`
	ClientIDIssuedAt        time.Time `json:"client_id_issued_at"`
	ClientSecretExpiresAt   time.Time `json:"client_secret_expires_at,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// RegistrationToken represents a client registration token
type RegistrationToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// TokenState represents stored token information
type TokenState struct {
	Token             string                 `json:"token"`
	TokenType         string                 `json:"token_type"` // "access", "refresh", "id"
	ClientID          string                 `json:"client_id"`
	UserID            string                 `json:"user_id,omitempty"`
	Scopes            []string               `json:"scopes,omitempty"`
	Audience          []string               `json:"audience,omitempty"`
	Subject           string                 `json:"subject,omitempty"`
	Issuer            string                 `json:"issuer,omitempty"` // Added missing field
	IssuedAt          time.Time              `json:"issued_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	NotBefore         time.Time              `json:"not_before,omitempty"`
	Active            bool                   `json:"active"`
	Extra             map[string]interface{} `json:"extra,omitempty"`
	ParentAccessToken string                 `json:"parent_access_token,omitempty"`
	Nonce             string                 `json:"nonce,omitempty"`
	AuthTime          *time.Time             `json:"auth_time,omitempty"`
	GrantType         string                 `json:"grant_type,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
}

// SessionState represents a user session
type SessionState struct {
	SessionID string                 `json:"session_id"`
	UserID    string                 `json:"user_id"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Active    bool                   `json:"active"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// Legacy types for backward compatibility (deprecated - use the State types above)
type AuthorizeRequest = AuthCodeState
type TokenInfo = TokenState
type Session = SessionState
