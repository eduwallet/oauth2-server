package config

import (
	"fmt"
	"net/http"
	"oauth2-server/internal/utils"
	"os"
	"strings"
)

// AttestationConfig represents the global attestation configuration
type AttestationConfig struct {
	Enabled bool                      `yaml:"enabled"`
	Clients []ClientAttestationConfig `yaml:"clients"`
}

// ClientAttestationConfig represents attestation configuration for a specific client
type ClientAttestationConfig struct {
	ClientID       string   `yaml:"client_id" json:"client_id"`
	AllowedMethods []string `yaml:"allowed_methods" json:"allowed_methods"`
	TrustAnchors   []string `yaml:"trust_anchors" json:"trust_anchors"`
	RequiredLevel  string   `yaml:"required_level,omitempty" json:"required_level,omitempty"`
}

// Validate validates the client attestation configuration
func (c *ClientAttestationConfig) Validate() error {
	// Note: client_id validation is handled by the registration handler
	// since it may be set automatically during registration

	if len(c.AllowedMethods) == 0 {
		return fmt.Errorf("at least one allowed_method is required")
	}

	validMethods := []string{"attest_jwt_client_auth", "attest_tls_client_auth"}
	for _, method := range c.AllowedMethods {
		found := false
		for _, valid := range validMethods {
			if method == valid {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid attestation method: %s", method)
		}
	}

	if len(c.TrustAnchors) == 0 {
		return fmt.Errorf("at least one trust anchor is required")
	}

	if c.RequiredLevel != "" {
		validLevels := []string{"low", "medium", "high"}
		found := false
		for _, level := range validLevels {
			if c.RequiredLevel == level {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid required_level: %s", c.RequiredLevel)
		}
	}

	return nil
}

// Validate validates the global attestation configuration
func (a *AttestationConfig) Validate() error {
	if !a.Enabled {
		return nil // No validation needed when disabled
	}

	// Allow attestation to be enabled without pre-configured clients
	// Clients can be registered dynamically with attestation configuration later

	// Validate each client configuration if any are present
	clientIDs := make(map[string]bool)
	for _, client := range a.Clients {
		// Check for duplicate client IDs
		if clientIDs[client.ClientID] {
			return fmt.Errorf("duplicate client_id in attestation config: %s", client.ClientID)
		}
		clientIDs[client.ClientID] = true

		// Validate individual client config
		if err := client.Validate(); err != nil {
			return fmt.Errorf("invalid attestation config for client %s: %w", client.ClientID, err)
		}
	}

	return nil
}

// Config holds the application configuration
type Config struct {
	// Server configuration
	Server   ServerConfig   `yaml:"server"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
	Database DatabaseConfig `yaml:"database"`

	// PublicBaseURL is the public base URL of the server (can be overridden by YAML)
	PublicBaseURL string

	// Clients loaded from YAML
	Clients []ClientConfig `yaml:"clients"`

	// Users loaded from YAML (only used in "local" mode)
	Users []UserConfig `yaml:"users"`

	// Upstream Provider (only used in "proxy" mode)
	UpstreamProvider UpstreamProviderConfig

	// Attestation configuration
	Attestation *AttestationConfig `yaml:"attestation,omitempty"`

	// CIMD / Client-Initiated Metadata Discovery configuration
	CIMD *CIMDConfig `yaml:"cimd,omitempty"`

	// Reverse Proxy Configuration (can be overridden by YAML)
	TrustProxyHeaders bool
	// PublicBaseURL     string
	ForceHTTPS     bool
	TrustedProxies string
}

// CIMDConfig holds configuration options for Client-Initiated Metadata Discovery
type CIMDConfig struct {
	Enabled               bool     `yaml:"enabled"`
	HttpPermitted         bool     `yaml:"http_permitted"`
	QueryPermitted        bool     `yaml:"query_permitted"`
	AllowlistEnabled      bool     `yaml:"allowlist_enabled"`
	Allowlist             []string `yaml:"allowlist"`
	MetadataPolicyEnabled bool     `yaml:"metadata_policy_enabled"`
	MetadataPolicy        string   `yaml:"metadata_policy"`
	CacheMaxSeconds       int      `yaml:"cache_max_seconds"`
	AlwaysRetrieved       bool     `yaml:"always_retrieved"`
	// Fetch rate limiting (per-host)
	FetchLimit         int `yaml:"fetch_limit"`
	FetchWindowSeconds int `yaml:"fetch_window_seconds"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port            int `yaml:"port"`
	ReadTimeout     int `yaml:"read_timeout"`
	WriteTimeout    int `yaml:"write_timeout"`
	ShutdownTimeout int `yaml:"shutdown_timeout"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	JWTSecret                      string `yaml:"jwt_signing_key"`
	TokenExpirySeconds             int    `yaml:"token_expiry_seconds"`
	RefreshTokenExpirySeconds      int    `yaml:"refresh_token_expiry_seconds"`
	DeviceCodeExpirySeconds        int    `yaml:"device_code_expiry_seconds"`
	AuthorizationCodeExpirySeconds int    `yaml:"authorization_code_expiry_seconds"`
	EnablePKCE                     bool   `yaml:"enable_pkce"`
	RequireHTTPS                   bool   `yaml:"require_https"`
	AllowSyntheticIDToken          bool   `yaml:"allow_synthetic_id_token"`

	// API protection settings
	APIKey                string `yaml:"api_key,omitempty" env:"API_KEY"`
	EnableRegistrationAPI bool   `yaml:"enable_registration_api" env:"ENABLE_REGISTRATION_API"`
	EnableTrustAnchorAPI  bool   `yaml:"enable_trust_anchor_api" env:"ENABLE_TRUST_ANCHOR_API"`

	// Privileged client for server operations
	PrivilegedClientID string `yaml:"privileged_client_id,omitempty"`

	// Encryption settings
	EncryptionKey string `yaml:"encryption_key"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	EnableAudit bool   `yaml:"enable_audit"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type string `yaml:"type"` // "memory" or "sqlite"
	Path string `yaml:"path"` // SQLite database file path (ignored for memory)
}

// ClientConfig represents a client configuration from YAML
type ClientConfig struct {
	ID                      string                   `yaml:"id"`
	Secret                  string                   `yaml:"secret"`
	Name                    string                   `yaml:"name"`
	Description             string                   `yaml:"description"`
	RedirectURIs            []string                 `yaml:"redirect_uris"`
	GrantTypes              []string                 `yaml:"grant_types"`
	ResponseTypes           []string                 `yaml:"response_types"`
	Scopes                  []string                 `yaml:"scopes"`
	Claims                  []string                 `yaml:"claims"`
	Audience                []string                 `yaml:"audience"`
	TokenEndpointAuthMethod string                   `yaml:"token_endpoint_auth_method"`
	Public                  bool                     `yaml:"public"`
	EnabledFlows            []string                 `yaml:"enabled_flows"`
	Enabled                 *bool                    `yaml:"enabled,omitempty"` // Pointer to distinguish between false and unset
	AttestationConfig       *ClientAttestationConfig `yaml:"attestation_config,omitempty"`
}

// ConfigClient is an alias for ClientConfig for backward compatibility
type ConfigClient = ClientConfig

// UserConfig represents a user configuration from YAML
type UserConfig struct {
	ID       string `yaml:"id"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Email    string `yaml:"email"`
	Name     string `yaml:"name"`
}

// UpstreamProviderConfig represents configuration for an upstream OAuth2 provider
type UpstreamProviderConfig struct {
	ProviderURL  string
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Metadata     map[string]interface{}
}

// IsEnabled returns whether this client is enabled (defaults to true if not specified)
func (c ClientConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true // Default to enabled if not specified
	}
	return *c.Enabled
}

// HasAttestationAuth returns whether this client uses attestation-based authentication
func (c ClientConfig) HasAttestationAuth() bool {
	return c.TokenEndpointAuthMethod == "attest_jwt_client_auth" ||
		c.TokenEndpointAuthMethod == "attest_tls_client_auth"
}

// ValidateRedirectURI validates a redirect URI against this client's registered URIs
func (c ClientConfig) ValidateRedirectURI(requestedURI string) bool {
	return utils.ValidateClientRedirectURI(requestedURI, c.RedirectURIs)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Security.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if len(c.Security.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters for security (current length: %d)", len(c.Security.JWTSecret))
	}

	if c.Security.EncryptionKey == "" {
		return fmt.Errorf("encryption key is required")
	}

	if len(c.Security.EncryptionKey) != 32 {
		return fmt.Errorf("encryption key must be exactly 32 bytes (256 bits) for AES-256")
	}

	// if c.Server.Port <= 0 || c.Server.Port > 65535 {
	// 	return fmt.Errorf("invalid server port: %d", c.Server.Port)
	// }

	// if c.Server.Host == "" {
	// 	return fmt.Errorf("server host is required")
	// }

	// Validate mode-specific configuration
	if c.IsLocalMode() {
		if len(c.Users) == 0 {
			return fmt.Errorf("local mode requires at least one user to be configured")
		}
		if c.UpstreamProvider.ProviderURL != "" {
			return fmt.Errorf("upstream_provider should not be configured in local mode")
		}
	} else if c.IsProxyMode() {
		// Check if upstream provider is configured either in YAML (legacy) or environment variables (new)
		hasYAMLConfig := c.UpstreamProvider.ProviderURL != "" && c.UpstreamProvider.ProviderURL != "https://example.com"
		hasEnvConfig := os.Getenv("UPSTREAM_PROVIDER_URL") != ""

		if !hasYAMLConfig && !hasEnvConfig {
			return fmt.Errorf("proxy mode requires upstream_provider.provider_url to be configured either in config.yaml or via UPSTREAM_PROVIDER_URL environment variable")
		}
		// Users can be configured in proxy mode but will be ignored
	}

	// Validate clients
	for i, client := range c.Clients {
		if client.ID == "" {
			return fmt.Errorf("client %d: client ID is required", i)
		}

		// Skip disabled clients
		if !client.IsEnabled() {
			continue
		}

		// Public clients don't need secrets, but confidential clients do
		// Exception: attestation-based auth doesn't require secrets
		if !client.Public && client.Secret == "" && !client.HasAttestationAuth() {
			return fmt.Errorf("client %s: client secret is required for confidential clients", client.ID)
		}

		// Validate grant types
		for _, grantType := range client.GrantTypes {
			if !isValidGrantType(grantType) {
				return fmt.Errorf("client %s: invalid grant type: %s", client.ID, grantType)
			}
		}

		// Validate token endpoint auth method
		if !isValidTokenEndpointAuthMethod(client.TokenEndpointAuthMethod) {
			return fmt.Errorf("client %s: invalid token endpoint auth method: %s", client.ID, client.TokenEndpointAuthMethod)
		}

		// Validate attestation configuration if using attestation auth
		if client.HasAttestationAuth() {
			if client.AttestationConfig == nil {
				return fmt.Errorf("client %s: attestation configuration required for attestation-based auth", client.ID)
			}
			if err := c.validateAttestationConfig(client); err != nil {
				return fmt.Errorf("client %s: %w", client.ID, err)
			}
		}

		// Authorization code flow requires redirect URIs
		if contains(client.GrantTypes, "authorization_code") && len(client.RedirectURIs) == 0 {
			return fmt.Errorf("client %s: redirect URIs required for authorization_code grant", client.ID)
		}

		// Validate that all Redirect URIs are absolute or normalized
		for _, uri := range client.RedirectURIs {
			if uri == "" {
				return fmt.Errorf("client %s: redirect URI cannot be empty", client.ID)
			}
			if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") && !strings.HasPrefix(uri, "/") {
				return fmt.Errorf("client %s: redirect URI must be absolute or normalized: %s", client.ID, uri)
			}
		}
	}

	// Validate attestation configuration if present
	if c.Attestation != nil {
		if err := c.Attestation.Validate(); err != nil {
			return fmt.Errorf("attestation configuration: %w", err)
		}
	}

	// Validate database configuration
	if err := c.validateDatabaseConfig(); err != nil {
		return fmt.Errorf("database configuration: %w", err)
	}

	return nil
}

// validateAttestationConfig validates attestation configuration for a client
func (c *Config) validateAttestationConfig(client ClientConfig) error {
	if client.AttestationConfig == nil {
		return fmt.Errorf("attestation config is nil")
	}

	return client.AttestationConfig.Validate()
}

// validateDatabaseConfig validates the database configuration
func (c *Config) validateDatabaseConfig() error {
	// Validate database type
	if c.Database.Type == "" {
		return fmt.Errorf("database type is required")
	}

	validTypes := []string{"memory", "sqlite"}
	if !contains(validTypes, c.Database.Type) {
		return fmt.Errorf("invalid database type '%s', must be one of: %s", c.Database.Type, strings.Join(validTypes, ", "))
	}

	// Validate database path for SQLite
	if c.Database.Type == "sqlite" {
		if c.Database.Path == "" {
			return fmt.Errorf("database path is required when using sqlite database type")
		}
		// Basic path validation - should not be just a directory separator or contain invalid characters
		if strings.TrimSpace(c.Database.Path) == "" {
			return fmt.Errorf("database path cannot be empty or only whitespace")
		}
		if strings.Contains(c.Database.Path, "..") {
			return fmt.Errorf("database path cannot contain '..' for security reasons")
		}
	}

	return nil
}

// Type alias for backward compatibility
type User = UserConfig

// GetEffectiveBaseURL returns the effective base URL considering proxy headers
func (c *Config) GetEffectiveBaseURL(r *http.Request) string {
	return utils.GetEffectiveBaseURL(c.PublicBaseURL, r)
}

// GetClientByID returns a client by ID
func (c *Config) GetClientByID(clientID string) (*ClientConfig, bool) {
	for _, client := range c.Clients {
		if client.ID == clientID {
			return &client, true
		}
	}
	return nil, false
}

// GetUserByUsername returns a user by username
func (c *Config) GetUserByUsername(username string) (*UserConfig, bool) {
	for _, user := range c.Users {
		if user.Username == username {
			return &user, true
		}
	}
	return nil, false
}

// GetUserByID returns a user by ID
func (c *Config) GetUserByID(userID string) (*UserConfig, bool) {
	for _, user := range c.Users {
		if user.ID == userID {
			return &user, true
		}
	}
	return nil, false
}

// GetFirstClient returns the first configured client (useful for testing)
func (c *Config) GetFirstClient() (*ClientConfig, bool) {
	if len(c.Clients) > 0 {
		return &c.Clients[0], true
	}
	return nil, false
}

// IsProxyMode returns true if the server is configured to proxy to an upstream provider
func (c *Config) IsProxyMode() bool {
	// Check if upstream provider is configured in YAML or environment variables
	return c.UpstreamProvider.ProviderURL != "" && c.UpstreamProvider.ProviderURL != "https://example.com"
}

// IsLocalMode returns true if the server is configured to use local users
func (c *Config) IsLocalMode() bool {
	return !c.IsProxyMode()
}

// SetDefaults sets default values for configuration options that are not specified
func (c *Config) SetDefaults() {
	// Set default security values
	if c.Security.TokenExpirySeconds == 0 {
		c.Security.TokenExpirySeconds = 3600 // 1 hour
	}
	if c.Security.RefreshTokenExpirySeconds == 0 {
		c.Security.RefreshTokenExpirySeconds = 86400 // 24 hours
	}
	if c.Security.AuthorizationCodeExpirySeconds == 0 {
		c.Security.AuthorizationCodeExpirySeconds = 600 // 10 minutes
	}
	if c.Security.DeviceCodeExpirySeconds == 0 {
		c.Security.DeviceCodeExpirySeconds = 1800 // 30 minutes
	}

	// Set default database values
	if c.Database.Type == "" {
		c.Database.Type = "memory" // Default to memory storex
	}
	if c.Database.Path == "" && c.Database.Type == "sqlite" {
		c.Database.Path = "oauth2.db" // Default SQLite path
	}

	// Set default API protection values (disabled by default for security)
	// These should be explicitly enabled by administrators
	if !c.Security.EnableRegistrationAPI && os.Getenv("ENABLE_REGISTRATION_API") == "" {
		// Default is false - registration API is disabled
		c.Security.EnableRegistrationAPI = false
	}
	if !c.Security.EnableTrustAnchorAPI && os.Getenv("ENABLE_TRUST_ANCHOR_API") == "" {
		// Default is false - trust anchor API is disabled
		c.Security.EnableTrustAnchorAPI = false
	}

	// Set default CIMD configuration
	if c.CIMD == nil {
		c.CIMD = &CIMDConfig{}
	}
	if c.CIMD.CacheMaxSeconds == 0 {
		c.CIMD.CacheMaxSeconds = 86400 // 1 day
	}
	if c.CIMD.FetchLimit == 0 {
		c.CIMD.FetchLimit = 60 // default requests per window
	}
	if c.CIMD.FetchWindowSeconds == 0 {
		c.CIMD.FetchWindowSeconds = 60 // default window in seconds
	}
}

func isValidGrantType(grantType string) bool {
	validGrantTypes := []string{
		"authorization_code",
		"client_credentials",
		"password",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:device_code",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
	return contains(validGrantTypes, grantType)
}

func isValidTokenEndpointAuthMethod(method string) bool {
	validMethods := []string{
		"client_secret_basic",
		"client_secret_post",
		"client_secret_jwt",
		"private_key_jwt",
		"none",
		"attest_jwt_client_auth", // New attestation method
		"attest_tls_client_auth", // New attestation method
	}
	return contains(validMethods, method)
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
