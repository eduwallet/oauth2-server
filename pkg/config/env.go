package config

import (
	"os"
	"strconv"
	"strings"
)

// LoadFromEnv loads configuration from environment variables and overrides YAML config
func (c *Config) LoadFromEnv() {
	// Server configuration overrides
	if publicBaseURL := os.Getenv("PUBLIC_BASE_URL"); publicBaseURL != "" {
		// c.Server.BaseURL = baseURL
		c.PublicBaseURL = publicBaseURL
	} else {
		// Default public base URL for development
		c.PublicBaseURL = "http://localhost:8080"
	}

	if port := os.Getenv("PORT"); port != "" {
		if portInt, err := strconv.Atoi(port); err == nil {
			c.Server.Port = portInt
		}
	} else {
		// Default port
		c.Server.Port = 8080
	}

	// Logging configuration overrides
	if loglevel := os.Getenv("LOG_LEVEL"); loglevel != "" {
		c.Logging.Level = loglevel
	}

	if logformat := os.Getenv("LOG_FORMAT"); logformat != "" {
		c.Logging.Format = logformat
	} else {
		// Default log format
		c.Logging.Format = "text"
	}

	if enableAudit := os.Getenv("ENABLE_AUDIT_LOGGING"); enableAudit != "" {
		c.Logging.EnableAudit = GetEnvBool("ENABLE_AUDIT_LOGGING", false)
	} else {
		// Default audit logging
		c.Logging.EnableAudit = false
	}

	// Database configuration overrides
	if storageType := os.Getenv("DATABASE_TYPE"); storageType != "" {
		c.Database.Type = storageType
	} else {
		// Default database type
		c.Database.Type = "memory"
	}

	if storagePath := os.ExpandEnv("${DATABASE_PATH}"); storagePath != "" {
		c.Database.Path = storagePath
	} else {
		// Default database path
		c.Database.Path = "oauth2-server.db"
	}

	// Proxy configuration overrides
	if trustHeaders := os.Getenv("TRUST_PROXY_HEADERS"); trustHeaders != "" {
		c.TrustProxyHeaders = GetEnvBool("TRUST_PROXY_HEADERS", true)
	}

	if forceHTTPS := os.Getenv("FORCE_HTTPS"); forceHTTPS != "" {
		c.ForceHTTPS = GetEnvBool("FORCE_HTTPS", false)
	}

	if trustedProxies := os.Getenv("TRUSTED_PROXIES"); trustedProxies != "" {
		c.TrustedProxies = trustedProxies
	}

	// Upstream provider configuration (moved from config.yaml for security)
	c.loadUpstreamProviderFromEnv()

	// CIMD (Client-Initiated Metadata Discovery) configuration
	// Environment variables:
	// CIMD_ENABLED, CIMD_HTTP_PERMITTED, CIMD_QUERY_PERMITTED, CIMD_ALLOWLIST (comma separated)
	// CIMD_METADATA_POLICY_ENABLED, CIMD_METADATA_POLICY, CIMD_CACHE_MAX_SECONDS, CIMD_ALWAYS_RETRIEVED
	if c.CIMD == nil {
		c.CIMD = &CIMDConfig{}
	}
	if v := os.Getenv("CIMD_ENABLED"); v != "" {
		c.CIMD.Enabled = GetEnvBool("CIMD_ENABLED", false)
	}
	if v := os.Getenv("CIMD_HTTP_PERMITTED"); v != "" {
		c.CIMD.HttpPermitted = GetEnvBool("CIMD_HTTP_PERMITTED", false)
	}
	if v := os.Getenv("CIMD_QUERY_PERMITTED"); v != "" {
		c.CIMD.QueryPermitted = GetEnvBool("CIMD_QUERY_PERMITTED", false)
	}
	if v := os.Getenv("CIMD_ALLOWLIST"); v != "" {
		c.CIMD.Allowlist = filterEmpty(strings.Split(v, ","))
		c.CIMD.AllowlistEnabled = true
	}
	if v := os.Getenv("CIMD_METADATA_POLICY_ENABLED"); v != "" {
		c.CIMD.MetadataPolicyEnabled = GetEnvBool("CIMD_METADATA_POLICY_ENABLED", false)
	}
	if v := os.Getenv("CIMD_METADATA_POLICY"); v != "" {
		c.CIMD.MetadataPolicy = v
	}
	if v := os.Getenv("CIMD_CACHE_MAX_SECONDS"); v != "" {
		if i := GetEnvInt("CIMD_CACHE_MAX_SECONDS", 0); i > 0 {
			c.CIMD.CacheMaxSeconds = i
		}
	}
	if v := os.Getenv("CIMD_ALWAYS_RETRIEVED"); v != "" {
		c.CIMD.AlwaysRetrieved = GetEnvBool("CIMD_ALWAYS_RETRIEVED", false)
	}

	if v := os.Getenv("CIMD_FETCH_LIMIT"); v != "" {
		if i := GetEnvInt("CIMD_FETCH_LIMIT", 0); i > 0 {
			c.CIMD.FetchLimit = i
		}
	}
	if v := os.Getenv("CIMD_FETCH_WINDOW_SECONDS"); v != "" {
		if i := GetEnvInt("CIMD_FETCH_WINDOW_SECONDS", 0); i > 0 {
			c.CIMD.FetchWindowSeconds = i
		}
	}

	// Security configuration overrides
	if encryptionKey := os.Getenv("ENCRYPTION_KEY"); encryptionKey != "" {
		c.Security.EncryptionKey = encryptionKey
	}

	if jwtKey := os.Getenv("JWT_SIGNING_KEY"); jwtKey != "" {
		c.Security.JWTSecret = jwtKey
	}

	// Set token expiry with validation (must be positive)
	expiry := GetEnvInt("TOKEN_EXPIRY_SECONDS", 3600)
	if expiry <= 0 {
		expiry = 3600
	}
	c.Security.TokenExpirySeconds = expiry

	// Set refresh token expiry with validation (must be positive)
	refreshExpiry := GetEnvInt("REFRESH_TOKEN_EXPIRY_SECONDS", 86400)
	if refreshExpiry <= 0 {
		refreshExpiry = 86400
	}
	c.Security.RefreshTokenExpirySeconds = refreshExpiry

	// Set device code expiry with validation (must be positive)
	deviceExpiry := GetEnvInt("DEVICE_CODE_EXPIRY_SECONDS", 600)
	if deviceExpiry <= 0 {
		deviceExpiry = 600
	}
	c.Security.DeviceCodeExpirySeconds = deviceExpiry

	// Set authorization code expiry with validation (must be positive)
	authzExpiry := GetEnvInt("AUTHORIZATION_CODE_EXPIRY_SECONDS", 600)
	if authzExpiry <= 0 {
		authzExpiry = 600
	}
	c.Security.AuthorizationCodeExpirySeconds = authzExpiry

	if requireHTTPS := os.Getenv("REQUIRE_HTTPS"); requireHTTPS != "" {
		c.Security.RequireHTTPS = GetEnvBool("REQUIRE_HTTPS", false)
	}

	if enablePKCE := os.Getenv("ENABLE_PKCE"); enablePKCE != "" {
		c.Security.EnablePKCE = GetEnvBool("ENABLE_PKCE", true)
	}

	if allowSynthetic := os.Getenv("ALLOW_SYNTHETIC_ID_TOKEN"); allowSynthetic != "" {
		c.Security.AllowSyntheticIDToken = GetEnvBool("ALLOW_SYNTHETIC_ID_TOKEN", false)
	}

	// API protection configuration
	if apiKey := os.Getenv("API_KEY"); apiKey != "" {
		c.Security.APIKey = apiKey
	} else {
		// Default API key for development
		c.Security.APIKey = "dev-api-key-change-in-production"
	}

	if enableRegistrationAPI := os.Getenv("ENABLE_REGISTRATION_API"); enableRegistrationAPI != "" {
		c.Security.EnableRegistrationAPI = GetEnvBool("ENABLE_REGISTRATION_API", false)
	}

	if enableTrustAnchorAPI := os.Getenv("ENABLE_TRUST_ANCHOR_API"); enableTrustAnchorAPI != "" {
		c.Security.EnableTrustAnchorAPI = GetEnvBool("ENABLE_TRUST_ANCHOR_API", false)
	}

	if privilegedClientID := os.Getenv("PRIVILEGED_CLIENT_ID"); privilegedClientID != "" {
		c.Security.PrivilegedClientID = privilegedClientID
	} else if c.Security.PrivilegedClientID == "" {
		// Default privileged client ID for development
		c.Security.PrivilegedClientID = "privileged-client"
	}

	// Add support for dynamic client configuration via environment variables
	c.loadClientsFromEnv()

	// Add support for dynamic user configuration via environment variables
	c.loadUsersFromEnv()
}

// loadClientsFromEnv loads additional clients from environment variables
func (c *Config) loadClientsFromEnv() {
	// Support for adding clients via environment variables
	// Format: CLIENT_<ID>_SECRET, CLIENT_<ID>_REDIRECT_URIS, etc.

	clientPrefix := "CLIENT_"
	envVars := os.Environ()
	clientEnvs := make(map[string]map[string]string)

	for _, env := range envVars {
		if strings.HasPrefix(env, clientPrefix) {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := parts[0]
			value := parts[1]

			// Extract client ID and property
			keyParts := strings.Split(key, "_")
			if len(keyParts) < 3 {
				continue
			}

			clientID := keyParts[1]
			property := strings.Join(keyParts[2:], "_")

			if clientEnvs[clientID] == nil {
				clientEnvs[clientID] = make(map[string]string)
			}
			clientEnvs[clientID][property] = value
		}
	}

	// Convert environment client configs to ClientConfig - FIXED VARIABLE NAME
	for clientID, props := range clientEnvs {
		if secret, hasSecret := props["SECRET"]; hasSecret {
			redirectURIs := filterEmpty(strings.Split(getOrDefault(props, "REDIRECT_URIS", ""), ","))
			grantTypes := filterEmpty(strings.Split(getOrDefault(props, "GRANT_TYPES", "authorization_code,refresh_token"), ","))
			responseTypes := filterEmpty(strings.Split(getOrDefault(props, "RESPONSE_TYPES", "code"), ","))
			scopes := filterEmpty(strings.Split(getOrDefault(props, "SCOPES", "openid,profile,email"), ","))

			clientConfig := ClientConfig{ // ← Fixed: use clientConfig instead of ConfigClient
				ID:                      clientID,
				Secret:                  secret,
				Name:                    getOrDefault(props, "NAME", "Environment Client "+clientID),
				RedirectURIs:            redirectURIs,
				GrantTypes:              grantTypes,
				ResponseTypes:           responseTypes,
				Scopes:                  scopes,
				TokenEndpointAuthMethod: "client_secret_basic",
				Public:                  false,
				EnabledFlows:            grantTypes,
			}

			c.Clients = append(c.Clients, clientConfig) // ← Fixed variable name
		}
	}
}

// loadUsersFromEnv loads additional users from environment variables
func (c *Config) loadUsersFromEnv() {
	// Support for adding users via environment variables
	// Format: USER_<ID>_USERNAME, USER_<ID>_PASSWORD, etc.

	userPrefix := "USER_"
	envVars := os.Environ()
	userEnvs := make(map[string]map[string]string)

	for _, env := range envVars {
		if strings.HasPrefix(env, userPrefix) {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := parts[0]
			value := parts[1]

			// Extract user ID and property
			keyParts := strings.Split(key, "_")
			if len(keyParts) < 3 {
				continue
			}

			userID := keyParts[1]
			property := strings.Join(keyParts[2:], "_")

			if userEnvs[userID] == nil {
				userEnvs[userID] = make(map[string]string)
			}
			userEnvs[userID][property] = value
		}
	}

	// Convert environment user configs to User
	for userID, props := range userEnvs {
		if username, hasUsername := props["USERNAME"]; hasUsername {
			userConfig := UserConfig{
				ID:       userID,
				Username: username,
				Password: getOrDefault(props, "PASSWORD", ""),
				Email:    getOrDefault(props, "EMAIL", username+"@example.com"),
				Name:     getOrDefault(props, "NAME", username),
			}
			c.Users = append(c.Users, userConfig)
		}
	}
}

// Helper function to get environment value or default
func getOrDefault(props map[string]string, key, defaultValue string) string {
	if value, exists := props[key]; exists {
		return value
	}
	return defaultValue
}

// Helper function to filter out empty strings from slice
func filterEmpty(slice []string) []string {
	var result []string
	for _, item := range slice {
		if strings.TrimSpace(item) != "" {
			result = append(result, strings.TrimSpace(item))
		}
	}
	return result
}

// GetEnvInt gets an environment variable as integer with default
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetEnvBool gets an environment variable as boolean with default
func GetEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// GetEnvString gets an environment variable as string with default
func GetEnvString(key string, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// loadUpstreamProviderFromEnv loads upstream provider configuration from environment variables
func (c *Config) loadUpstreamProviderFromEnv() {
	// Check if upstream provider is configured via environment variables
	providerURL := os.Getenv("UPSTREAM_PROVIDER_URL")
	if providerURL != "" {
		c.UpstreamProvider = UpstreamProviderConfig{
			ProviderURL:  providerURL,
			ClientID:     GetEnvString("UPSTREAM_CLIENT_ID", ""),
			ClientSecret: GetEnvString("UPSTREAM_CLIENT_SECRET", ""),
			CallbackURL:  GetEnvString("UPSTREAM_CALLBACK_URL", ""),
		}
	}
}
