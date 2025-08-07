package config

import (
	"os"
	"strconv"
	"strings"
)

// LoadFromEnv loads configuration from environment variables and overrides YAML config
func (c *Config) LoadFromEnv() {
	// Server configuration overrides
	if baseURL := os.Getenv("PUBLIC_BASE_URL"); baseURL != "" {
		c.BaseURL = baseURL
		c.Server.BaseURL = baseURL
		if c.YAMLConfig != nil {
			c.YAMLConfig.Server.BaseURL = baseURL
		}
	}

	if port := os.Getenv("PORT"); port != "" {
		c.Port = port
		if portInt, err := strconv.Atoi(port); err == nil {
			c.Server.Port = portInt
			if c.YAMLConfig != nil {
				c.YAMLConfig.Server.Port = portInt
			}
		}
	}

	if host := os.Getenv("HOST"); host != "" {
		c.Host = host
		c.Server.Host = host
		if c.YAMLConfig != nil {
			c.YAMLConfig.Server.Host = host
		}
	}

	// Proxy configuration overrides
	if trustHeaders := os.Getenv("TRUST_PROXY_HEADERS"); trustHeaders != "" {
		c.TrustProxyHeaders = GetEnvBool("TRUST_PROXY_HEADERS", true)
		if c.YAMLConfig != nil && c.YAMLConfig.Proxy != nil {
			c.YAMLConfig.Proxy.TrustHeaders = c.TrustProxyHeaders
		}
	}

	if publicBaseURL := os.Getenv("PUBLIC_BASE_URL"); publicBaseURL != "" {
		c.PublicBaseURL = publicBaseURL
		if c.YAMLConfig != nil && c.YAMLConfig.Proxy != nil {
			c.YAMLConfig.Proxy.PublicBaseURL = publicBaseURL
		}
	}

	if forceHTTPS := os.Getenv("FORCE_HTTPS"); forceHTTPS != "" {
		c.ForceHTTPS = GetEnvBool("FORCE_HTTPS", false)
		if c.YAMLConfig != nil && c.YAMLConfig.Proxy != nil {
			c.YAMLConfig.Proxy.ForceHTTPS = c.ForceHTTPS
		}
	}

	if trustedProxies := os.Getenv("TRUSTED_PROXIES"); trustedProxies != "" {
		c.TrustedProxies = trustedProxies
		// Note: Store in main config as ProxyConfig doesn't have TrustedProxies field
	}

	// Security configuration overrides
	if jwtKey := os.Getenv("JWT_SIGNING_KEY"); jwtKey != "" {
		c.Security.JWTSecret = jwtKey // Fix: use JWTSecret instead of JWTSigningKey
		if c.YAMLConfig != nil {
			c.YAMLConfig.Security.JWTSecret = jwtKey
		}
	}

	if tokenExpiry := os.Getenv("TOKEN_EXPIRY_SECONDS"); tokenExpiry != "" {
		if expiry := GetEnvInt("TOKEN_EXPIRY_SECONDS", 3600); expiry > 0 {
			c.Security.TokenExpirySeconds = expiry // Fix: use TokenExpirySeconds instead of TokenExpiry
			if c.YAMLConfig != nil {
				c.YAMLConfig.Security.TokenExpirySeconds = expiry
			}
		}
	}

	if refreshExpiry := os.Getenv("REFRESH_TOKEN_EXPIRY_SECONDS"); refreshExpiry != "" {
		if expiry := GetEnvInt("REFRESH_TOKEN_EXPIRY_SECONDS", 86400); expiry > 0 {
			c.Security.RefreshTokenExpirySeconds = expiry // Fix: use RefreshTokenExpirySeconds instead of RefreshTokenExpiry
			if c.YAMLConfig != nil {
				c.YAMLConfig.Security.RefreshTokenExpirySeconds = expiry
			}
		}
	}

	if requireHTTPS := os.Getenv("REQUIRE_HTTPS"); requireHTTPS != "" {
		c.Security.RequireHTTPS = GetEnvBool("REQUIRE_HTTPS", false)
		if c.YAMLConfig != nil {
			c.YAMLConfig.Security.RequireHTTPS = c.Security.RequireHTTPS
		}
	}

	if enablePKCE := os.Getenv("ENABLE_PKCE"); enablePKCE != "" {
		c.Security.EnablePKCE = GetEnvBool("ENABLE_PKCE", true)
		if c.YAMLConfig != nil {
			c.YAMLConfig.Security.EnablePKCE = c.Security.EnablePKCE
		}
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

// GetEnvStringSlice gets an environment variable as string slice (comma-separated) with default
func GetEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return filterEmpty(strings.Split(value, ","))
	}
	return defaultValue
}
