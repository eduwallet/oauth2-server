package config

import (
	"fmt"
	"net/http"
	"oauth2-server/internal/utils"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AttestationConfig represents the global attestation configuration
type AttestationConfig struct {
	Enabled bool                      `yaml:"enabled"`
	Clients []ClientAttestationConfig `yaml:"clients"`
}

// ClientAttestationConfig represents attestation configuration for a specific client
type ClientAttestationConfig struct {
	ClientID       string   `yaml:"client_id"`
	AllowedMethods []string `yaml:"allowed_methods"`
	TrustAnchors   []string `yaml:"trust_anchors"`
	RequiredLevel  string   `yaml:"required_level,omitempty"`
}

// Validate validates the client attestation configuration
func (c *ClientAttestationConfig) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required for attestation config")
	}

	if len(c.AllowedMethods) == 0 {
		return fmt.Errorf("at least one allowed_method is required")
	}

	validMethods := []string{"attest_jwt_client_auth", "attest_tls_client_auth", "mock"}
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

	if len(a.Clients) == 0 {
		return fmt.Errorf("at least one client must be configured when attestation is enabled")
	}

	// Validate each client configuration
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
	Server   ServerConfig
	Security SecurityConfig
	Logging  LoggingConfig

	// Legacy fields for backward compatibility
	BaseURL string
	Port    string
	Host    string

	// Dynamic configuration from YAML
	YAMLConfig *YAMLConfig

	// Clients loaded from YAML
	Clients []ClientConfig

	// Users loaded from YAML
	Users []UserConfig

	// Attestation configuration
	Attestation *AttestationConfig

	// Reverse Proxy Configuration (can be overridden by YAML)
	TrustProxyHeaders bool
	PublicBaseURL     string
	ForceHTTPS        bool
	TrustedProxies    string
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port            int    `yaml:"port"`
	Host            string `yaml:"host"`
	BaseURL         string `yaml:"base_url"`
	ReadTimeout     int    `yaml:"read_timeout"`
	WriteTimeout    int    `yaml:"write_timeout"`
	ShutdownTimeout int    `yaml:"shutdown_timeout"`
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
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	EnableAudit bool   `yaml:"enable_audit"`
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

// YAMLConfig represents the raw YAML configuration structure
type YAMLConfig struct {
	Server      ServerConfig       `yaml:"server"`
	Security    SecurityConfig     `yaml:"security"`
	Logging     LoggingConfig      `yaml:"logging"`
	Clients     []ClientConfig     `yaml:"clients"`
	Users       []UserConfig       `yaml:"users"`
	Proxy       *ProxyConfig       `yaml:"proxy,omitempty"`
	Attestation *AttestationConfig `yaml:"attestation,omitempty"`
}

// ProxyConfig holds proxy-related configuration
type ProxyConfig struct {
	TrustHeaders bool `yaml:"trust_headers"`
	ForceHTTPS   bool `yaml:"force_https"`
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

	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.Host == "" {
		return fmt.Errorf("server host is required")
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

	return nil
}

// validateAttestationConfig validates attestation configuration for a client
func (c *Config) validateAttestationConfig(client ClientConfig) error {
	if client.AttestationConfig == nil {
		return fmt.Errorf("attestation config is nil")
	}

	return client.AttestationConfig.Validate()
}

// Type alias for backward compatibility
type User = UserConfig

// GetEffectiveBaseURL returns the effective base URL considering proxy headers
func (c *Config) GetEffectiveBaseURL(r *http.Request) string {
	return utils.GetEffectiveBaseURL(c.Server.BaseURL, r)
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

// GetFirstUser returns the first configured user (useful for testing)
func (c *Config) GetFirstUser() (*UserConfig, bool) {
	if len(c.Users) > 0 {
		return &c.Users[0], true
	}
	return nil, false
}

// LoadYAMLConfig loads YAML configuration from a file
func LoadYAMLConfig(configPath string) (*YAMLConfig, error) {
	if configPath == "" {
		configPath = "config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML config file: %w", err)
	}

	var yamlConfig YAMLConfig
	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return &yamlConfig, nil
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func isValidGrantType(grantType string) bool {
	validGrantTypes := []string{
		"authorization_code",
		"client_credentials",
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
