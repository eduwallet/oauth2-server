package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete configuration structure
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Security SecurityConfig `yaml:"security"`
	Proxy    ProxyConfig    `yaml:"proxy"`
	Logging  LoggingConfig  `yaml:"logging"`
	Clients  []ClientConfig `yaml:"clients"`
	Users    []UserConfig   `yaml:"users"`
}

// ServerConfig contains server-related configuration
type ServerConfig struct {
	BaseURL         string `yaml:"base_url"`
	Port            int    `yaml:"port"`
	Host            string `yaml:"host"`
	ReadTimeout     int    `yaml:"read_timeout"`
	WriteTimeout    int    `yaml:"write_timeout"`
	ShutdownTimeout int    `yaml:"shutdown_timeout"`
}

// DatabaseConfig contains database-related configuration
type DatabaseConfig struct {
	Type             string `yaml:"type"`              // "sqlite", "postgres", "memory" (default: "memory")
	SQLitePath       string `yaml:"sqlite_path"`       // Path to SQLite database file
	PostgresHost     string `yaml:"postgres_host"`     // PostgreSQL host
	PostgresPort     int    `yaml:"postgres_port"`     // PostgreSQL port
	PostgresDB       string `yaml:"postgres_db"`       // PostgreSQL database name
	PostgresUser     string `yaml:"postgres_user"`     // PostgreSQL username
	PostgresPassword string `yaml:"postgres_password"` // PostgreSQL password
	PostgresSSLMode  string `yaml:"postgres_sslmode"`  // PostgreSQL SSL mode (disable, require, verify-ca, verify-full)
	CleanupInterval  int    `yaml:"cleanup_interval"`  // Cleanup interval in minutes (default: 60)
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	JWTSigningKey                  string                    `yaml:"jwt_signing_key"`
	TokenExpirySeconds             int                       `yaml:"token_expiry_seconds"`
	RefreshTokenExpirySeconds      int                       `yaml:"refresh_token_expiry_seconds"`
	DeviceCodeExpirySeconds        int                       `yaml:"device_code_expiry_seconds"`
	AuthorizationCodeExpirySeconds int                       `yaml:"authorization_code_expiry_seconds"`
	EnablePKCE                     bool                      `yaml:"enable_pkce"`
	RequireHTTPS                   bool                      `yaml:"require_https"`
	DynamicRegistration            DynamicRegistrationConfig `yaml:"dynamic_registration"`
}

// DynamicRegistrationConfig contains dynamic client registration settings
type DynamicRegistrationConfig struct {
	Enabled                   bool     `yaml:"enabled"`
	RequireInitialAccessToken bool     `yaml:"require_initial_access_token"`
	InitialAccessToken        string   `yaml:"initial_access_token"`
	DefaultTokenLifetime      int      `yaml:"default_token_lifetime"`
	AllowedGrantTypes         []string `yaml:"allowed_grant_types"`
	AllowedResponseTypes      []string `yaml:"allowed_response_types"`
	AllowedScopes             []string `yaml:"allowed_scopes"`
	RequireRedirectURI        bool     `yaml:"require_redirect_uri"`
	ClientSecretExpirySeconds int      `yaml:"client_secret_expiry_seconds"`
}

// ProxyConfig contains proxy-related settings
type ProxyConfig struct {
	TrustHeaders   bool     `yaml:"trust_headers"`
	PublicBaseURL  string   `yaml:"public_base_url"`
	ForceHTTPS     bool     `yaml:"force_https"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	EnableAudit bool   `yaml:"enable_audit"`
}

// ClientConfig represents an OAuth2 client configuration
type ClientConfig struct {
	ID                      string   `yaml:"id"`
	Secret                  string   `yaml:"secret"`
	Name                    string   `yaml:"name"`
	Description             string   `yaml:"description"`
	RedirectURIs            []string `yaml:"redirect_uris"`
	GrantTypes              []string `yaml:"grant_types"`
	ResponseTypes           []string `yaml:"response_types"`
	Scopes                  []string `yaml:"scopes"`
	Audience                []string `yaml:"audience"`
	TokenEndpointAuthMethod string   `yaml:"token_endpoint_auth_method"`
	Public                  bool     `yaml:"public"`
	EnabledFlows            []string `yaml:"enabled_flows"`
}

// UserConfig represents a user configuration
type UserConfig struct {
	ID       string   `yaml:"id"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Name     string   `yaml:"name"`
	Email    string   `yaml:"email"`
	Enabled  bool     `yaml:"enabled"`
	Roles    []string `yaml:"roles"`
	Scopes   []string `yaml:"scopes"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if not specified
	setDefaults(&config)

	return &config, nil
}

// setDefaults sets default values for configuration
func setDefaults(config *Config) {
	if config.Server.Port == 0 {
		config.Server.Port = 8080
	}
	if config.Server.Host == "" {
		config.Server.Host = "localhost"
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 30
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 30
	}
	if config.Server.ShutdownTimeout == 0 {
		config.Server.ShutdownTimeout = 5
	}
	if config.Security.TokenExpirySeconds == 0 {
		config.Security.TokenExpirySeconds = 3600
	}
	if config.Security.RefreshTokenExpirySeconds == 0 {
		config.Security.RefreshTokenExpirySeconds = 86400
	}
	if config.Security.DeviceCodeExpirySeconds == 0 {
		config.Security.DeviceCodeExpirySeconds = 600
	}
	if config.Security.AuthorizationCodeExpirySeconds == 0 {
		config.Security.AuthorizationCodeExpirySeconds = 300
	}
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
}

// GetAccessTokenLifespan returns the access token lifespan as time.Duration
func (s *SecurityConfig) GetAccessTokenLifespan() time.Duration {
	return time.Duration(s.TokenExpirySeconds) * time.Second
}

// GetRefreshTokenLifespan returns the refresh token lifespan as time.Duration
func (s *SecurityConfig) GetRefreshTokenLifespan() time.Duration {
	return time.Duration(s.RefreshTokenExpirySeconds) * time.Second
}

// GetAuthorizationCodeLifespan returns the authorization code lifespan as time.Duration
func (s *SecurityConfig) GetAuthorizationCodeLifespan() time.Duration {
	return time.Duration(s.AuthorizationCodeExpirySeconds) * time.Second
}

// GetDeviceCodeLifespan returns the device code lifespan as time.Duration
func (s *SecurityConfig) GetDeviceCodeLifespan() time.Duration {
	return time.Duration(s.DeviceCodeExpirySeconds) * time.Second
}
