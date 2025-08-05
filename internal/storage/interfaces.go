package storage

import (
	"time"

	"oauth2-demo/internal/config"
)

// Storage interface defines the methods for persisting OAuth2 data
type Storage interface {
	// Authorization codes
	StoreAuthCode(code string, authReq *AuthorizeRequest) error
	GetAuthCode(code string) (*AuthorizeRequest, error)
	DeleteAuthCode(code string) error

	// Device codes
	StoreDeviceCode(deviceCode string, state *DeviceCodeState) error
	GetDeviceCode(deviceCode string) (*DeviceCodeState, error)
	GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, string, error)
	UpdateDeviceCode(deviceCode string, state *DeviceCodeState) error
	DeleteDeviceCode(deviceCode string) error

	// Dynamic clients
	StoreDynamicClient(clientID string, client *config.ClientConfig) error
	GetDynamicClient(clientID string) (*config.ClientConfig, error)
	DeleteDynamicClient(clientID string) error

	// Registration tokens
	StoreRegistrationToken(token, clientID string) error
	GetClientIDByRegistrationToken(token string) (string, error)
	DeleteRegistrationToken(token string) error

	// OAuth2 Tokens (Access, Refresh, ID tokens)
	StoreToken(tokenInfo *TokenInfo) error
	GetToken(token string) (*TokenInfo, error)
	GetTokensByClientID(clientID string) ([]*TokenInfo, error)
	GetTokensByUserID(userID string) ([]*TokenInfo, error)
	UpdateTokenStatus(token string, active bool) error
	DeleteToken(token string) error
	DeleteTokensByClientID(clientID string) error
	DeleteTokensByUserID(userID string) error

	// Cleanup expired entries
	CleanupExpired() error

	// Close the storage
	Close() error
}

// AuthorizeRequest represents an OAuth2 authorization request
type AuthorizeRequest struct {
	ClientID            string    `json:"client_id"`
	ResponseType        string    `json:"response_type"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	State               string    `json:"state"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// DeviceCodeResponse represents the response for device authorization
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceCodeState represents the internal state of a device authorization
type DeviceCodeState struct {
	*DeviceCodeResponse
	ClientID    string    `json:"client_id"`
	Scope       string    `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Authorized  bool      `json:"authorized"`
	UserID      string    `json:"user_id"`      // Set when user authorizes the device
	AccessToken string    `json:"access_token"` // Set when authorization is complete
}

// TokenInfo represents stored token information
type TokenInfo struct {
	Token     string                 `json:"token"`
	TokenType string                 `json:"token_type"` // "access", "refresh", "id"
	ClientID  string                 `json:"client_id"`
	UserID    string                 `json:"user_id,omitempty"`
	Scope     string                 `json:"scope,omitempty"`
	Audience  []string               `json:"audience,omitempty"`
	Subject   string                 `json:"subject,omitempty"`
	IssuedAt  time.Time              `json:"issued_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	NotBefore time.Time              `json:"not_before,omitempty"`
	Active    bool                   `json:"active"`
	Extra     map[string]interface{} `json:"extra,omitempty"`

	// For refresh tokens
	ParentAccessToken string `json:"parent_access_token,omitempty"`

	// For ID tokens
	Nonce    string     `json:"nonce,omitempty"`
	AuthTime *time.Time `json:"auth_time,omitempty"`

	// Metadata
	GrantType string    `json:"grant_type,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
