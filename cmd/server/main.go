package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus" // Add this import

	"oauth2-server/internal/auth"
	"oauth2-server/internal/flows"
	"oauth2-server/internal/handlers"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// Create a logger instance
var log = logrus.New()

var (
	// Application configuration
	cfg *config.Config

	// OAuth2 provider and stores
	oauth2Provider fosite.OAuth2Provider
	clientStore    *store.ClientStore
	authCodeStore  *store.AuthCodeStore
	tokenStore     *store.TokenStore

	// OAuth2 flows
	authCodeFlow      *flows.AuthorizationCodeFlow
	clientCredsFlow   *flows.ClientCredentialsFlow
	refreshTokenFlow  *flows.RefreshTokenFlow
	tokenExchangeFlow *flows.TokenExchangeFlow
	deviceCodeFlow    *flows.DeviceCodeFlow

	// Documentation handler
	docsHandler *handlers.DocsHandler

	// Token handlers
	tokenHandlers *handlers.TokenHandlers

	// Registration handler
	registrationHandlers *handlers.RegistrationHandlers
)

// CompositeStore combines our custom ClientStore with Fosite's MemoryStore
type CompositeStore struct {
	*store.ClientStore
	*storage.MemoryStore
}

// GetClient implements fosite.ClientManager
func (c *CompositeStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return c.ClientStore.GetClient(ctx, id)
}

func main() {
	log.Println("🚀 Starting OAuth2 Server...")

	// Load configuration from YAML
	var err error
	cfg, err = config.Load()
	if err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("❌ Invalid configuration: %v", err)
	}

	// Access logging configuration correctly:
	logLevel := cfg.Logging.Level          // ✅ Correct
	logFormat := cfg.Logging.Format        // ✅ Correct
	enableAudit := cfg.Logging.EnableAudit // ✅ Correct

	// Initialize logger based on config
	switch logLevel {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}

	// Set log format
	if logFormat == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	log.Printf("✅ Configuration loaded successfully")
	log.Printf("🔧 Log Level: %s, Format: %s, Audit: %t", logLevel, logFormat, enableAudit)

	// Initialize stores
	initializeStores()

	// Load clients from configuration
	if err := clientStore.LoadClientsFromConfig(cfg.Clients); err != nil {
		log.Fatalf("❌ Failed to load clients from config: %v", err)
	}

	// Initialize OAuth2 provider
	if err := initializeOAuth2Provider(); err != nil {
		log.Fatalf("❌ Failed to initialize OAuth2 provider: %v", err)
	}

	// Initialize flows
	initializeFlows()

	// Setup routes
	setupRoutes()

	// Start server
	log.Printf("🌐 OAuth2 server starting on port %d", cfg.Server.Port)
	log.Printf("🔗 Authorization endpoint: %s/auth", cfg.Server.BaseURL)
	log.Printf("🎫 Token endpoint: %s/token", cfg.Server.BaseURL)
	log.Printf("📱 Device authorization: %s/device_authorization", cfg.Server.BaseURL)
	log.Printf("🔧 Client registration: %s/register", cfg.Server.BaseURL)
	log.Printf("🏥 Health check: %s/health", cfg.Server.BaseURL)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.Server.Port), nil); err != nil {
		log.Fatalf("❌ Server failed to start: %v", err)
	}
}

func initializeStores() {
	clientStore = store.NewClientStore()
	authCodeStore = store.NewAuthCodeStore()

	// Token store with configurable expiry
	expiryConfig := map[string]time.Duration{
		"access_token":       time.Duration(cfg.Security.TokenExpirySeconds) * time.Second,
		"refresh_token":      time.Duration(cfg.Security.RefreshTokenExpirySeconds) * time.Second,
		"authorization_code": time.Duration(cfg.Security.AuthorizationCodeExpirySeconds) * time.Second,
	}
	tokenStore = store.NewTokenStore(expiryConfig)
}

func initializeOAuth2Provider() error {
	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create memory store for non-client data (sessions, codes, etc.)
	memoryStore := storage.NewMemoryStore()

	// Create a composite store that uses our clientStore for clients
	// and memoryStore for everything else
	compositeStore := &CompositeStore{
		ClientStore: clientStore,
		MemoryStore: memoryStore,
	}

	// Configure OAuth2 provider
	config := &fosite.Config{
		AccessTokenLifespan:      time.Hour,
		RefreshTokenLifespan:     time.Hour * 24 * 30,
		AuthorizeCodeLifespan:    time.Minute * 10,
		GlobalSecret:             []byte(cfg.Security.JWTSecret + "-padded-to-32-bytes-for-hmac-security"), // Ensure adequate length
		AccessTokenIssuer:        cfg.Server.BaseURL,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	// Build OAuth2 provider with all grant types
	oauth2Provider = compose.Compose(
		config,
		compositeStore,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(
				func(ctx context.Context) (interface{}, error) {
					return privateKey, nil
				},
				config,
			),
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)

	return nil
}

func initializeFlows() {
	// Initialize token handlers
	tokenHandlers = handlers.NewTokenHandlers(clientStore, tokenStore, cfg)

	authCodeFlow = flows.NewAuthorizationCodeFlow(oauth2Provider, cfg)

	clientCredsFlow = flows.NewClientCredentialsFlow(clientStore, tokenStore, cfg)
	refreshTokenFlow = flows.NewRefreshTokenFlow(clientStore, tokenStore, cfg)
	tokenExchangeFlow = flows.NewTokenExchangeFlow(clientStore, tokenStore, cfg)
	deviceCodeFlow = flows.NewDeviceCodeFlow(clientStore, tokenStore, cfg)

	// Start cleanup timer for expired device codes
	deviceCodeFlow.StartCleanupTimer()

	// Initialize documentation handler
	docsHandler = handlers.NewDocsHandler(cfg, clientStore)

	// Initialize registration handlers
	registrationHandlers = handlers.NewRegistrationHandlers(clientStore, cfg)

	log.Printf("✅ OAuth2 flows initialized")
}

func setupRoutes() {
	// OAuth2 endpoints with proxy awareness
	http.HandleFunc("/.well-known/oauth-authorization-server", proxyAwareMiddleware(wellKnownHandler))
	http.HandleFunc("/.well-known/openid-configuration", proxyAwareMiddleware(wellKnownHandler))
	http.HandleFunc("/.well-known/jwks.json", proxyAwareMiddleware(jwksHandler))
	http.HandleFunc("/auth", proxyAwareMiddleware(authHandler))
	http.HandleFunc("/token", proxyAwareMiddleware(tokenHandler))
	http.HandleFunc("/userinfo", proxyAwareMiddleware(userInfoHandler))
	http.HandleFunc("/callback", proxyAwareMiddleware(callbackHandler))
	http.HandleFunc("/revoke", proxyAwareMiddleware(tokenHandlers.HandleTokenRevocation))
	http.HandleFunc("/introspect", proxyAwareMiddleware(tokenHandlers.HandleTokenIntrospection))

	// Device flow endpoints
	http.HandleFunc("/device_authorization", proxyAwareMiddleware(deviceAuthHandler))
	http.HandleFunc("/device", proxyAwareMiddleware(deviceHandler))

	// Registration endpoints
	http.HandleFunc("/register", proxyAwareMiddleware(registrationHandler))
	http.HandleFunc("/register/", proxyAwareMiddleware(registrationConfigHandler))

	// Testing endpoints
	http.HandleFunc("/client1/auth", proxyAwareMiddleware(client1AuthHandler))
	http.HandleFunc("/client1/callback", proxyAwareMiddleware(callbackHandler))

	// Health and utility endpoints
	http.HandleFunc("/health", proxyAwareMiddleware(healthHandler))
	http.HandleFunc("/", proxyAwareMiddleware(homeHandler))

	// Client management API endpoints (must come before general /api/ route)
	http.HandleFunc("/api/clients", proxyAwareMiddleware(clientManagementHandler))
	http.HandleFunc("/api/clients/", proxyAwareMiddleware(clientManagementHandler))

	// General API endpoints (protected with authentication)
	http.HandleFunc("/api/", proxyAwareMiddleware(apiHandler))

	// Documentation endpoints
	log.Printf("📚 Registering /docs and /docs/ endpoints")
	http.HandleFunc("/docs", proxyAwareMiddleware(docsWrapperHandler))
	http.HandleFunc("/docs/", proxyAwareMiddleware(docsWrapperHandler))

	// Add admin endpoints
	if cfg != nil {
		clientHandler := handlers.NewClientHandler(clientStore, cfg)
		if clientHandler != nil {
			http.HandleFunc("/admin/clients", clientHandler.HandleClients)
			http.HandleFunc("/admin/client", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					clientHandler.HandleClientUpdate(w, r)
				} else {
					clientHandler.HandleClient(w, r)
				}
			})
			http.HandleFunc("/admin/client/edit", clientHandler.HandleEditClient)
			http.HandleFunc("/admin/config", clientHandler.HandleClientConfig)
			log.Printf("🔧 Client endpoints enabled at /admin/*")
		} else {
			log.Printf("⚠️ Failed to create client handler")
		}
	}

	// Use the existing tokenHandlers instance initialized in initializeFlows()
	http.HandleFunc("/token/stats", proxyAwareMiddleware(tokenHandlers.HandleTokenStats))

	http.HandleFunc("/stats", proxyAwareMiddleware(func(w http.ResponseWriter, r *http.Request) {
		statsHandler := handlers.StatsHandler{
			TokenStore:  tokenStore,
			ClientStore: clientStore,
			Config:      cfg,
		}
		statsHandler.ServeHTTP(w, r)
	}))

}

// Helper wrapper functions for your existing handlers
func authHandler(w http.ResponseWriter, r *http.Request) {
	authCodeFlow.HandleAuthorization(w, r)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	authCodeFlow.HandleCallback(w, r)
}

func deviceAuthHandler(w http.ResponseWriter, r *http.Request) {
	deviceCodeFlow.HandleAuthorization(w, r)
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	registrationHandlers.HandleRegistration(w, r)
}

func registrationConfigHandler(w http.ResponseWriter, r *http.Request) {
	registrationHandlers.HandleClientConfiguration(w, r)
}

func docsWrapperHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("📚 /docs endpoint hit: %s", r.URL.Path)
	docsHandler.ServeHTTP(w, r)
}

func clientManagementHandler(w http.ResponseWriter, r *http.Request) {
	// Route client management API calls to the docs handler
	if r.URL.Path == "/api/clients" {
		docsHandler.HandleClientsAPI(w, r)
	} else if len(r.URL.Path) > 13 && r.URL.Path[:13] == "/api/clients/" {
		docsHandler.HandleClientAPI(w, r)
	} else {
		http.NotFound(w, r)
	}
}

// Token handler that routes to appropriate flow
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteInvalidRequestError(w, "Failed to parse request")
		return
	}

	grantType := r.FormValue("grant_type")
	log.Printf("🔄 Processing token request with grant_type: %s", grantType)

	switch grantType {
	case "client_credentials":
		tokenHandlers.HandleClientCredentials(w, r)
	case "refresh_token":
		tokenHandlers.HandleRefreshToken(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		tokenHandlers.HandleTokenExchange(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		deviceCodeFlow.HandleToken(w, r)
	default:
		// Handle standard grant types with Fosite
		handleStandardTokenRequest(w, r)
	}
}

func handleStandardTokenRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accessRequest, err := oauth2Provider.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
	if err != nil {
		log.Printf("❌ Error creating access request: %v", err)
		oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	response, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.Printf("❌ Error creating access response: %v", err)
		oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	oauth2Provider.WriteAccessResponse(ctx, w, accessRequest, response)
}

// Device handler for user verification
func deviceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		showDeviceVerificationForm(w, r)
		return
	}

	if r.Method == "POST" {
		handleDeviceVerification(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func showDeviceVerificationForm(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	errorMsg := r.URL.Query().Get("error")

	html := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Device Verification</title>
	<style>
		body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
		.form-group { margin-bottom: 15px; }
		label { display: block; margin-bottom: 5px; font-weight: bold; }
		input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
		button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
		button:hover { background-color: #0056b3; }
		.error { color: red; margin-bottom: 15px; }
		.info { color: #666; margin-bottom: 15px; }
	</style>
</head>
<body>
	<h2>📱 Device Verification</h2>
	<div class="info">Please enter the user code displayed on your device and authenticate:</div>`

	if errorMsg != "" {
		html += fmt.Sprintf(`<div class="error">%s</div>`, errorMsg)
	}

	html += `
	<form method="post">
		<div class="form-group">
			<label for="user_code">User Code:</label>
			<input type="text" id="user_code" name="user_code" value="` + userCode + `" placeholder="Enter user code" required>
		</div>
		<div class="form-group">
			<label for="username">Username:</label>
			<input type="text" id="username" name="username" placeholder="john.doe" required>
		</div>
		<div class="form-group">
			<label for="password">Password:</label>
			<input type="password" id="password" name="password" placeholder="password123" required>
		</div>
		<button type="submit">Authorize Device</button>
	</form>
	
	<p><a href="/">← Back to Home</a></p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Failed to parse form: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userCode := r.FormValue("user_code")
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Normalize user code - trim, uppercase, and ensure consistent formatting
	userCode = strings.TrimSpace(strings.ToUpper(userCode))

	// Validate user code format
	if err := utils.ValidateUserCode(userCode); err != nil {
		http.Redirect(w, r, "/device?error=Invalid user code format", http.StatusFound)
		return
	}

	// Ensure user code has the hyphen format for device flow lookup
	if len(userCode) == 8 && !strings.Contains(userCode, "-") {
		userCode = fmt.Sprintf("%s-%s", userCode[:4], userCode[4:])
	}

	// Authenticate user against configured users
	user := authenticateUserFromConfig(username, password)
	if user == nil {
		http.Redirect(w, r, "/device?error=Invalid username or password", http.StatusFound)
		return
	}

	// Authorize the device
	if deviceCodeFlow.AuthorizeDevice(userCode, user.ID) {
		showDeviceVerificationSuccess(w, r)
	} else {
		http.Redirect(w, r, "/device?error=Invalid or expired user code", http.StatusFound)
	}
}

// Add helper function for user authentication
func authenticateUserFromConfig(username, password string) *config.User {
	if user, found := cfg.GetUserByUsername(username); found {
		// In a real implementation, you'd hash and compare passwords properly
		if user.Password == password {
			return user
		}
	}
	return nil
}

func showDeviceVerificationSuccess(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Device Authorized</title>
	<style>
		body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; text-align: center; }
		.success { color: green; font-size: 24px; margin-bottom: 20px; }
		.info { color: #666; margin-bottom: 15px; }
	</style>
</head>
<body>
	<div class="success">✅ Device Successfully Authorized!</div>
	<div class="info">You can now return to your device. The application should receive the access token shortly.</div>
	<p><a href="/">← Back to Home</a></p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Enhanced userinfo handler with proper user lookup
func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	// Extract bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	// Validate the access token (simplified version)
	if err := auth.ValidateAccessToken(token); err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// For now, return the first user's info or a default user
	// In a real implementation, you'd extract user ID from the token
	var userInfo map[string]interface{}
	if len(cfg.Users) > 0 {
		user := cfg.Users[0]
		userInfo = map[string]interface{}{
			"sub":      user.ID,
			"name":     user.Name,
			"email":    user.Email,
			"username": user.Username,
		}
	} else {
		// Fallback if no users configured
		userInfo = map[string]interface{}{
			"sub":   "default-user",
			"name":  "Default User",
			"email": "default@example.com",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// Well-known handler
func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	// Get the effective base URL (proxy-aware)
	baseURL := cfg.GetEffectiveBaseURL(r)

	wellKnown := map[string]interface{}{
		// OAuth2 Authorization Server Metadata (RFC 8414)
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/auth",
		"token_endpoint":         baseURL + "/token",
		"userinfo_endpoint":      baseURL + "/userinfo",
		"jwks_uri":               baseURL + "/.well-known/jwks.json",
		"registration_endpoint":  baseURL + "/register",
		"revocation_endpoint":    baseURL + "/revoke",
		"introspection_endpoint": baseURL + "/introspect",

		// Device Flow (RFC 8628)
		"device_authorization_endpoint":    baseURL + "/device_authorization",
		"device_verification_uri":          baseURL + "/device",
		"device_verification_uri_complete": baseURL + "/device?user_code={user_code}",

		// Supported scopes
		"scopes_supported": []string{
			"openid", "profile", "email", "offline_access",
			"api:read", "api:write", "admin",
		},

		// Supported response types
		"response_types_supported": []string{
			"code", "token", "id_token",
			"code token", "code id_token", "token id_token",
			"code token id_token",
		},

		// Supported grant types
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// Token endpoint authentication methods
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"client_secret_jwt",
			"none",
		},

		// Token endpoint signing algorithms
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		// PKCE support
		"code_challenge_methods_supported": []string{
			"plain", "S256",
		},

		// OpenID Connect specific metadata
		"subject_types_supported": []string{
			"public", "pairwise",
		},

		"id_token_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		"id_token_encryption_alg_values_supported": []string{
			"RSA1_5", "RSA-OAEP", "A128KW", "A192KW", "A256KW",
		},

		"id_token_encryption_enc_values_supported": []string{
			"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
			"A128GCM", "A192GCM", "A256GCM",
		},

		"userinfo_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		"request_object_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		"response_modes_supported": []string{
			"query", "fragment", "form_post",
		},

		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website",
			"email", "email_verified", "gender", "birthdate", "zoneinfo",
			"locale", "phone_number", "phone_number_verified", "address",
			"updated_at",
		},

		"claims_parameter_supported":            true,
		"request_parameter_supported":           true,
		"request_uri_parameter_supported":       false,
		"require_request_uri_registration":      false,
		"claims_locales_supported":              []string{"en-US", "en-GB", "de-DE", "fr-FR"},
		"ui_locales_supported":                  []string{"en-US", "en-GB", "de-DE", "fr-FR"},
		"display_values_supported":              []string{"page", "popup", "touch", "wap"},
		"acr_values_supported":                  []string{"0", "1", "2"},
		"frontchannel_logout_supported":         true,
		"frontchannel_logout_session_supported": true,
		"backchannel_logout_supported":          false,
		"backchannel_logout_session_supported":  false,

		// Additional OAuth2 features
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic", "client_secret_post",
		},

		"revocation_endpoint_auth_methods_supported": []string{
			"client_secret_basic", "client_secret_post",
		},

		// Token Exchange (RFC 8693)
		"token_exchange_grant_types_supported": []string{
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// Custom extensions with proxy-aware URLs
		"service_documentation": baseURL + "/docs",
		"op_policy_uri":         baseURL + "/policy",
		"op_tos_uri":            baseURL + "/terms",
	}

	json.NewEncoder(w).Encode(wellKnown)
}

// JWKS handler
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "oauth2-server-key",
				"alg": "RS256",
				"n":   "example-modulus",
				"e":   "AQAB",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}

// Health handler
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"base_url":  cfg.Server.BaseURL,
		"clients":   len(clientStore.ListClients()),
	}

	json.NewEncoder(w).Encode(response)
}

// Home handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Generate user list from configuration
	var userListHTML strings.Builder
	if len(cfg.Users) > 0 {
		userListHTML.WriteString("<h3>👥 Available Test Users:</h3><ul>")
		for _, user := range cfg.Users {
			userListHTML.WriteString(fmt.Sprintf(
				"<li><strong>%s</strong> (%s) - Password: <code>%s</code></li>",
				user.Username, user.Name, user.Password))
		}
		userListHTML.WriteString("</ul>")
	} else {
		userListHTML.WriteString("<p><em>No test users configured in YAML</em></p>")
	}

	// Generate client list from configuration
	var clientListHTML strings.Builder
	if len(cfg.Clients) > 0 {
		clientListHTML.WriteString("<h3>🔑 Configured Clients:</h3><ul>")
		for _, client := range cfg.Clients {
			clientListHTML.WriteString(fmt.Sprintf(
				"<li><strong>%s</strong> - %s<br><small>Grant Types: %s</small></li>",
				client.ID, client.Name, strings.Join(client.GrantTypes, ", ")))
		}
		clientListHTML.WriteString("</ul>")
	} else {
		clientListHTML.WriteString("<p><em>No clients configured in YAML</em></p>")
	}

	homeHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OAuth2 Server</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
		.container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		h1 { color: #333; text-align: center; margin-bottom: 30px; }
		.section { margin-bottom: 30px; padding: 20px; background-color: #f8f9fa; border-radius: 6px; }
		.btn { display: inline-block; padding: 10px 20px; margin: 5px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; }
		.btn:hover { background-color: #0056b3; }
		.endpoint { font-family: monospace; background-color: #e9ecef; padding: 8px; border-radius: 3px; }
		ul { margin: 10px 0; }
		li { margin: 8px 0; }
		code { background-color: #f1f3f4; padding: 2px 4px; border-radius: 2px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>🚀 OAuth2 Authorization Server</h1>
		
		<div class="section">
			<h2>📋 Server Information</h2>
			<p><strong>Base URL:</strong> %s</p>
			<p><strong>Version:</strong> Development</p>
			<p><strong>Status:</strong> ✅ Running</p>
		</div>

		<div class="section">
			%s
		</div>

		<div class="section">
			%s
		</div>
		
		<div class="section">
			<h3>🔗 Quick Test Links</h3>
			<a href="/docs" class="btn">Operations...</a>
			<a href="/.well-known/oauth-authorization-server" class="btn">Discovery Document</a>
			<a href="/health" class="btn">Health Check</a>
		</div>
		
		<div class="section">
			<h3>📚 API Endpoints</h3>
			<ul>
				<li><span class="endpoint">GET /.well-known/oauth-authorization-server</span> - OAuth2 Discovery</li>
				<li><span class="endpoint">GET /.well-known/openid-configuration</span> - OIDC Discovery</li>
				<li><span class="endpoint">GET /.well-known/jwks.json</span> - JWKS</li>
			</ul>
		</div>

		<!-- Fancy Server Stats Section -->
		<div class="stats-section" style="margin-top:30px;">
		  <h2 style="text-align:center;">🚦 Server Stats</h2>
		  <div id="stats-cards" style="display:flex; gap:24px; justify-content:center; flex-wrap:wrap; margin-top:20px;">
		    <div class="stat-card" id="stat-tokens">
		      <div class="stat-icon">🔑</div>
		      <div class="stat-label">Tokens</div>
		      <div class="stat-value" id="stats-tokens-value">...</div>
		    </div>
		    <div class="stat-card" id="stat-clients">
		      <div class="stat-icon">🧩</div>
		      <div class="stat-label">Clients</div>
		      <div class="stat-value" id="stats-clients-value">...</div>
		    </div>
		    <div class="stat-card" id="stat-users">
		      <div class="stat-icon">👤</div>
		      <div class="stat-label">Users</div>
		      <div class="stat-value" id="stats-users-value">...</div>
		    </div>
		  </div>
		</div>
		<style>
		  .stat-card {
		    background: #fff;
		    border-radius: 12px;
		    box-shadow: 0 2px 8px rgba(0,0,0,0.07);
		    padding: 24px 32px;
		    min-width: 140px;
		    text-align: center;
		    transition: box-shadow 0.2s;
		  }
		  .stat-card:hover {
		    box-shadow: 0 4px 16px rgba(0,0,0,0.13);
		  }
		  .stat-icon {
		    font-size: 2.2em;
		    margin-bottom: 8px;
		  }
		  .stat-label {
		    font-size: 1.1em;
		    color: #555;
		    margin-bottom: 6px;
		    font-weight: 500;
		  }
		  .stat-value {
		    font-size: 2em;
		    font-weight: bold;
		    color: #007bff;
		  }
		</style>
		<script>
		function loadStats() {
		  fetch('/stats')
		    .then(r => r.json())
		    .then(stats => {
		      // Use the correct attribute for tokens
		      document.getElementById('stats-tokens-value').innerText =
		        stats.tokens?.tokens?.total ?? (typeof stats.tokens.tokens.total === "number" ? stats.tokens.tokens.total : "—");
		      document.getElementById('stats-clients-value').innerText =
		        stats.clients?.total ?? (typeof stats.clients === "number" ? stats.clients : "—");
		      document.getElementById('stats-users-value').innerText =
		        stats.users?.total ?? (typeof stats.users === "number" ? stats.users : stats.users ?? "—");
		    })
		    .catch(() => {
		      document.getElementById('stats-tokens-value').innerText = '—';
		      document.getElementById('stats-clients-value').innerText = '—';
		      document.getElementById('stats-users-value').innerText = '—';
		    });
		}
		document.addEventListener('DOMContentLoaded', loadStats);
		</script>
	</div>
</body>
</html>`, cfg.Server.BaseURL, userListHTML.String(), clientListHTML.String())

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(homeHTML))
}

// Client 1 auth handler
func client1AuthHandler(w http.ResponseWriter, r *http.Request) {
	// Find the first client from configuration or use default
	var clientID string
	var redirectURI string

	if len(cfg.Clients) > 0 {
		client := cfg.Clients[0]
		clientID = client.ID
		if len(client.RedirectURIs) > 0 {
			redirectURI = client.RedirectURIs[0]
		} else {
			redirectURI = cfg.Server.BaseURL + "/client1/callback"
		}
	} else {
		// Fallback to default values
		clientID = "frontend-app"
		redirectURI = cfg.Server.BaseURL + "/client1/callback"
	}

	authURL := fmt.Sprintf("%s/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile+email&state=random-state",
		cfg.Server.BaseURL, clientID, redirectURI)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// API handler with authentication
func apiHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Access token required", http.StatusUnauthorized)
		return
	}

	token, err := auth.ExtractBearerToken(authHeader)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	if err := auth.ValidateAccessToken(token); err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"message": "Hello from protected API!",
		"token":   token[:20] + "...",
		"time":    time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Middleware for proxy awareness
func proxyAwareMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Store original values
		originalHost := r.Host
		originalScheme := r.URL.Scheme

		// Handle X-Forwarded-Proto (HTTP/HTTPS)
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			r.URL.Scheme = proto
			if proto == "https" {
				r.TLS = &tls.ConnectionState{} // Indicate HTTPS to the application
			}
		}

		// Handle X-Forwarded-Host (hostname and port)
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			r.Host = host
			r.URL.Host = host
		}

		// Handle X-Forwarded-For (original client IP)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in the chain (original client)
			if ips := strings.Split(xff, ","); len(ips) > 0 {
				r.RemoteAddr = strings.TrimSpace(ips[0])
			}
		}

		// Handle X-Real-IP (alternative to X-Forwarded-For)
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			r.RemoteAddr = realIP
		}

		// Handle X-Forwarded-Port
		if port := r.Header.Get("X-Forwarded-Port"); port != "" {
			// Update host to include the forwarded port if not already present
			if !strings.Contains(r.Host, ":") {
				r.Host = r.Host + ":" + port
				r.URL.Host = r.Host
			}
		}

		// Update the config's BaseURL for this request if needed
		if r.URL.Scheme != "" && r.Host != "" {
			originalBaseURL := cfg.Server.BaseURL
			cfg.Server.BaseURL = r.URL.Scheme + "://" + r.Host

			// Restore original BaseURL after request
			defer func() {
				cfg.Server.BaseURL = originalBaseURL
			}()
		}

		// Log proxy information for debugging
		log.Printf("🔄 Proxy-aware request: %s %s (Original: %s://%s, Forwarded: %s://%s)",
			r.Method, r.RequestURI, originalScheme, originalHost, r.URL.Scheme, r.Host)

		handler(w, r)
	}
}

// Add a helper function to get the current request's base URL
func getRequestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	host := r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	return scheme + "://" + host
}
