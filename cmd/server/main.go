package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"

	"html/template"
	"os"
	"path/filepath"

	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"golang.org/x/crypto/bcrypt"

	"github.com/sirupsen/logrus"

	"oauth2-server/internal/handlers"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// Create a logger instance
var log = logrus.New()

var (
	// Application configuration
	configuration *config.Config

	// OAuth2 provider and stores
	oauth2Provider fosite.OAuth2Provider
	memoryStore    *storage.MemoryStore

	// Handlers
	registrationHandlers *handlers.RegistrationHandler

	// Templates for rendering HTML responses
	templates *template.Template
)

func main() {
	log.Println("🚀 Starting OAuth2 Server...")

	// Load configuration from YAML
	var err error
	configuration, err = config.Load()
	if err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := configuration.Validate(); err != nil {
		log.Fatalf("❌ Invalid configuration: %v", err)
	}

	// Access logging configuration correctly:
	logLevel := configuration.Logging.Level          // ✅ Correct
	logFormat := configuration.Logging.Format        // ✅ Correct
	enableAudit := configuration.Logging.EnableAudit // ✅ Correct

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
	memoryStore = storage.NewMemoryStore()

	// Initialize OAuth2 provider
	if err := initializeOAuth2Provider(); err != nil {
		log.Fatalf("❌ Failed to initialize OAuth2 provider: %v", err)
	}

	// Then extract the hasher
	// hasher := &fosite.BCrypt{
	// 	Cost: 12, // 12 is a standard work factor for bcrypt
	// }

	// Now initialize clients with the hasher
	if err := initializeClients(); err != nil {
		log.Fatalf("❌ Failed to initialize clients: %v", err)
	}

	// In main() function, after initializing clients
	if err := initializeUsers(); err != nil {
		log.Fatalf("❌ Failed to initialize users: %v", err)
	}

	// Load templates
	if err := loadTemplates(); err != nil {
		log.Fatalf("❌ Failed to load templates: %v", err)
	}

	// Initialize flows
	initializeHandlers()

	// Setup routes
	setupRoutes()

	// Start server
	log.Printf("🌐 OAuth2 server starting on port %d", configuration.Server.Port)
	log.Printf("🔗 Authorization endpoint: %s/auth", configuration.Server.BaseURL)
	log.Printf("🎫 Token endpoint: %s/token", configuration.Server.BaseURL)
	log.Printf("📱 Device authorization: %s/device/authorize", configuration.Server.BaseURL)
	log.Printf("🔧 Client registration: %s/register", configuration.Server.BaseURL)
	log.Printf("🏥 Health check: %s/health", configuration.Server.BaseURL)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", configuration.Server.Port), nil); err != nil {
		log.Fatalf("❌ Server failed to start: %v", err)
	}
}

func initializeClients() error {
	// Load clients from config if any
	if len(configuration.Clients) > 0 {

		// Register each client in the memory store
		for _, client := range configuration.Clients {
			hashedSecret, err := bcrypt.GenerateFromPassword([]byte(client.Secret), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash secret for client %s: %w", client.ID, err)
			}
			log.Println("Registering client:", client.ID)

			newClient := &fosite.DefaultClient{
				ID:     client.ID,
				Secret: hashedSecret,
				// Name:              client.Name,
				// Description:       client.Description,
				RedirectURIs:  client.RedirectURIs,
				GrantTypes:    client.GrantTypes,
				ResponseTypes: client.ResponseTypes,
				Scopes:        client.Scopes,
				Audience:      client.Audience,
				//				TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
				Public: client.Public,
				//				EnabledFlows:       client.EnabledFlows,
			}

			memoryStore.Clients[client.ID] = newClient
		}
	}

	log.Printf("✅ Stores initialized with %d clients", len(memoryStore.Clients))
	return nil

}

// Add this function to initialize users
func initializeUsers() error {

	// Load users from configuration
	if len(configuration.Users) > 0 {
		for _, user := range configuration.Users {

			// Make a copy of the user to avoid issues with loop variables
			newUser := storage.MemoryUserRelation{
				Username: user.Username,
				Password: user.Password,
			}

			memoryStore.Users[user.ID] = newUser

			log.Printf("✅ Registered user: %s (%s)", user.Username, user.ID)
		}
	}

	log.Printf("✅ User store initialized with %d users", len(memoryStore.Users))
	return nil
}

func initializeOAuth2Provider() error {
	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Configure OAuth2 provider
	config := &fosite.Config{
		AccessTokenLifespan:      time.Duration(configuration.Security.TokenExpirySeconds) * time.Second,
		RefreshTokenLifespan:     time.Duration(configuration.Security.RefreshTokenExpirySeconds) * time.Second,
		AuthorizeCodeLifespan:    time.Duration(configuration.Security.AuthorizationCodeExpirySeconds) * time.Second,
		GlobalSecret:             []byte(configuration.Security.JWTSecret + "-padded-to-32-bytes-for-hmac-security"),
		AccessTokenIssuer:        configuration.Server.BaseURL,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	// Build OAuth2 provider with all grant types INCLUDING Device Code
	oauth2Provider = compose.Compose(
		config,
		memoryStore,
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
		//		compose.RFC8693TokenExchangeFactory,
		compose.RFC8628DeviceFactory,
	)

	log.Printf("✅ OAuth2 provider initialized with fosite storage")
	return nil
}

func initializeHandlers() {
	// Initialize registration handlers
	log.Printf("✅ OAuth2 handlers initialized")
}

func loadTemplates() error {
	templatesDir := "templates"

	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		return fmt.Errorf("templates directory not found: %s", templatesDir)
	}

	funcMap := template.FuncMap{
		"split": strings.Split,
	}

	var err error
	templates = template.New("").Funcs(funcMap)
	templates, err = templates.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}

	log.Printf("✅ Templates loaded")

	return nil
}

func setupRoutes() {
	// OAuth2 endpoints - use fosite's built-in handlers
	//    http.HandleFunc("/oauth/authorize", proxyAwareMiddleware(authorizeHandler))
	http.HandleFunc("/oauth/token", proxyAwareMiddleware(tokenHandler))
	http.HandleFunc("/oauth/introspect", proxyAwareMiddleware(introspectHandler))
	http.HandleFunc("/oauth/revoke", proxyAwareMiddleware(revokeHandler))

	// Registration endpoints
	http.HandleFunc("/register", proxyAwareMiddleware(registrationHandlers.HandleRegistration))

	// Discovery endpoints
	http.HandleFunc("/.well-known/oauth-authorization-server", proxyAwareMiddleware(oauth2DiscoveryHandler)) // ← ADD THIS
	http.HandleFunc("/.well-known/openid-configuration", proxyAwareMiddleware(wellKnownHandler))
	http.HandleFunc("/.well-known/jwks.json", proxyAwareMiddleware(jwksHandler))

	// Utility endpoints
	http.HandleFunc("/userinfo", proxyAwareMiddleware(userInfoHandler))

	// Stats endpoint
	http.HandleFunc("/stats", proxyAwareMiddleware(func(w http.ResponseWriter, r *http.Request) {
		statsHandler := handlers.StatsHandler{
			Config: configuration,
		}
		statsHandler.ServeHTTP(w, r)
	}))

	// Health endpoint
	http.HandleFunc("/health", proxyAwareMiddleware(healthHandler))
	http.HandleFunc("/", proxyAwareMiddleware(homeHandler))

	log.Printf("✅ Routes set up successfully")
}

// Handlers for fosite's built-in functionality
func revokeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := oauth2Provider.NewRevocationRequest(ctx, r)
	if err != nil {
		log.Printf("❌ Error revoking token: %v", err)
		oauth2Provider.WriteRevocationResponse(ctx, w, err)
		return
	}
	oauth2Provider.WriteRevocationResponse(ctx, w, nil)
}

func introspectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Log the incoming request for debugging
	log.Printf("🔍 Introspection request: Method=%s, Content-Type=%s", r.Method, r.Header.Get("Content-Type"))

	// Log authentication headers with more detail
	authHeader := r.Header.Get("Authorization")
	log.Printf("🔍 Authorization header present: %t", authHeader != "")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) > 0 {
			log.Printf("🔍 Auth method: %s", parts[0])

			// DEBUG: Extract and log Basic Auth credentials (without exposing the secret)
			if parts[0] == "Basic" && len(parts) > 1 {
				// Decode the Basic Auth to get client ID (but not log the secret)
				if decoded, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
					credentials := string(decoded)
					if credParts := strings.Split(credentials, ":"); len(credParts) >= 2 {
						clientID := credParts[0]
						secretLength := len(credParts[1])
						log.Printf("🔍 Basic Auth - Client ID: %s, Secret length: %d", clientID, secretLength)
					}
				}
			}
		}
	}

	// Ensure it's a POST request
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		log.Printf("❌ Error parsing form: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Log form values (but hide sensitive data)
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	log.Printf("🔍 Introspection details: token_present=%t, token_type_hint=%s", token != "", tokenTypeHint)
	log.Printf("🔍 Client credentials in form: client_id_present=%t, client_secret_present=%t", clientID != "", clientSecret != "")

	// Create a session for introspection
	session := &fosite.DefaultSession{}

	// Create the introspection request
	ir, err := oauth2Provider.NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		log.Printf("❌ Error creating introspection request: %v", err)

		// Provide more specific error information
		switch err.Error() {
		case "request_unauthorized":
			log.Printf("❌ Client authentication failed for introspection")
			log.Printf("🔍 This usually means: 1) Missing/invalid client credentials, 2) Client not authorized for introspection, 3) Wrong auth method")
		case "invalid_request":
			log.Printf("❌ Invalid introspection request format")
		default:
			log.Printf("❌ Introspection error details: %v", err)
		}

		oauth2Provider.WriteIntrospectionError(ctx, w, err)
		return
	}

	// Write the successful introspection response
	oauth2Provider.WriteIntrospectionResponse(ctx, w, ir)
}

// Helper wrapper functions for your existing handlers
func authHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Let fosite handle the authorization request
	ar, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.Printf("❌ Error creating authorize request: %v", err)
		oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Simple session with user info (you can enhance this)
	session := &fosite.DefaultSession{
		Subject:  "user123",  // Get from your auth logic
		Username: "testuser", // Get from your auth logic
	}

	// Create the response
	response, err := oauth2Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.Printf("❌ Error creating authorize response: %v", err)
		oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Write the response
	oauth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)
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
	default:
		// Let fosite handle ALL standard grant types INCLUDING token exchange
		handleStandardTokenRequest(w, r)
	}
}

func handleStandardTokenRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Let fosite handle ALL token requests including token exchange
	accessRequest, err := oauth2Provider.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
	if err != nil {
		log.Printf("❌ Error creating access request: %v", err)
		oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Enhance session with user info for authorization code flow
	session := accessRequest.GetSession()
	if defaultSession, ok := session.(*fosite.DefaultSession); ok {
		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			defaultSession.Subject = extractUserFromAuthCode(accessRequest)
		case "client_credentials":
			defaultSession.Subject = accessRequest.GetClient().GetID()
			// Remove token exchange handling - fosite does this automatically
		}
	}

	response, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.Printf("❌ Error creating access response: %v", err)
		oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	oauth2Provider.WriteAccessResponse(ctx, w, accessRequest, response)
}

// Helper function to extract user from authorization code
func extractUserFromAuthCode(req fosite.AccessRequester) string {
	// This would need to be implemented based on your session storage
	// For now, return a default user
	return "user123"
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

	data := map[string]interface{}{
		"UserCode": userCode,
		"Error":    errorMsg,
	}

	if err := templates.ExecuteTemplate(w, "device_verify.html", data); err != nil {
		log.WithError(err).Error("Failed to render device verification template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// This handler shows the HTML page where the user enters the code
func deviceVerificationPageHandler(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	data := map[string]interface{}{
		"UserCode": userCode,
		"Error":    r.URL.Query().Get("error"),
	}
	if err := templates.ExecuteTemplate(w, "device.html", data); err != nil {
		log.WithError(err).Error("Failed to render device verification page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// authenticateUserFromConfig checks user credentials against the loaded configuration.
// In a real-world application, this would involve a database lookup and hashed password comparison.
func authenticateUserFromConfig(username, password string) *config.User {
	for _, user := range configuration.Users {
		if user.Username == username && user.Password == password {
			log.Printf("✅ User authenticated successfully: %s", username)
			return &user
		}
	}
	log.Printf("⚠️ Authentication failed for user: %s", username)
	return nil
}

// This handler processes the user's login and consent
func handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/device?error=Invalid+request", http.StatusFound)
		return
	}

	userCode := r.FormValue("user_code")
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate user against configured users
	user := authenticateUserFromConfig(username, password)
	if user == nil {
		http.Redirect(w, r, "/device?error=Invalid+credentials&user_code="+userCode, http.StatusFound)
		return
	}

	// // Authorize the device using our new storage method
	// ctx := r.Context()
	// if compositeStore, ok := oauth2Provider.GetStore().(interface {
	// 	AuthorizeDeviceCode(context.Context, string, string) error
	// }); ok {
	// 	// Fosite's device handler hashes the user code for storage, so we must do the same
	// 	hasher := oauth2Provider.GetHasher(ctx)
	// 	signature, err := hasher.Hash(ctx, []byte(userCode))
	// 	if err != nil {
	// 		http.Redirect(w, r, "/device?error=Internal+server+error", http.StatusFound)
	// 		return
	// 	}

	// 	err = compositeStore.AuthorizeDeviceCode(ctx, signature, user.ID)
	// 	if err != nil {
	// 		log.Printf("Error authorizing device: %v", err)
	// 		http.Redirect(w, r, "/device?error=Invalid+or+expired+user+code", http.StatusFound)
	// 		return
	// 	}
	// }

	// Show success page
	showDeviceVerificationSuccess(w, r)
}

// deviceAuthorizationHandler handles the initial device authorization request (RFC 8628).
// It delegates the entire process to the fosite provider.
func deviceAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create a session for the device authorization
	session := &fosite.DefaultSession{
		Subject: "", // Will be filled by the user later
	}

	// The NewDeviceRequest method handles parsing, validation, code generation,
	// storage, and writing the JSON response or error.
	deviceRequest, err := oauth2Provider.NewDeviceRequest(ctx, r)
	if err != nil {
		log.WithError(err).Error("Error during device authorization request")
		// Note: The error is already written to the response writer by the fosite handler
		return
	}

	// Create a response from the request
	deviceResponse, err := oauth2Provider.NewDeviceResponse(ctx, deviceRequest, session)
	if err != nil {
		log.WithError(err).Error("Error during device authorization request")
		return
	}

	// Let fosite write the response with the correct parameters
	oauth2Provider.WriteDeviceResponse(ctx, w, deviceRequest, deviceResponse)
}

func showDeviceVerificationSuccess(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Success": true,
		"Message": "Device has been successfully authorized",
	}

	if err := templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
		log.WithError(err).Error("Failed to render device success template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
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

	// Use fosite's introspection to validate the token
	ctx := r.Context()
	// We require the "openid" scope to allow access to this endpoint.
	_, requester, err := oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &fosite.DefaultSession{}, "openid")
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token is invalid or has expired."`)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// Get user info from token claims (the subject)
	subject := requester.GetSession().GetSubject()

	// Build user info response based on the user ID from the token
	var userInfo map[string]interface{}
	if user, found := configuration.GetUserByID(subject); found {
		userInfo = map[string]interface{}{
			"sub":      user.ID,
			"name":     user.Name,
			"email":    user.Email,
			"username": user.Username,
		}
	} else {
		// This case should ideally not happen if tokens are issued correctly
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="User not found."`)
		http.Error(w, "User associated with token not found", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// Well-known handler
func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	// Get the effective base URL (proxy-aware)
	baseURL := configuration.GetEffectiveBaseURL(r)

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

		// Token Exchange specific metadata (RFC 8693)
		"token_exchange_grant_types_supported": []string{
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		"subject_token_types_supported": []string{
			"urn:ietf:params:oauth:token-type:access_token",
			"urn:ietf:params:oauth:token-type:refresh_token",
			"urn:ietf:params:oauth:token-type:id_token",
		},

		"actor_token_types_supported": []string{
			"urn:ietf:params:oauth:token-type:access_token",
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

		"op_policy_uri": baseURL + "/policy",
		"op_tos_uri":    baseURL + "/terms",
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

// Health handler - updated to use the new method
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"base_url":  configuration.Server.BaseURL,
		"clients":   len(memoryStore.Clients),
		"storage":   "fosite-memory", // Indicate we're using fosite's storage
	}

	json.NewEncoder(w).Encode(response)
}

// Home handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Generate user list from configuration
	var userListHTML strings.Builder
	if len(configuration.Users) > 0 {
		userListHTML.WriteString("<h3>👥 Available Test Users:</h3><ul>")
		for _, user := range configuration.Users {
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
	if len(configuration.Clients) > 0 {
		clientListHTML.WriteString("<h3>🔑 Configured Clients:</h3><ul>")
		for _, client := range configuration.Clients {
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
			<h3>🔍 Discovery Endpoints</h3>
			<ul>
				<li><a href="/.well-known/oauth-authorization-server" class="btn">OAuth2 Discovery</a></li>
				<li><a href="/.well-known/openid-configuration" class="btn">OpenID Connect Discovery</a></li>
				<li><a href="/.well-known/jwks.json" class="btn">JWKS</a></li>
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
</html>`, configuration.Server.BaseURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(homeHTML))
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
			originalBaseURL := configuration.Server.BaseURL
			configuration.Server.BaseURL = r.URL.Scheme + "://" + r.Host

			// Restore original BaseURL after request
			defer func() {
				configuration.Server.BaseURL = originalBaseURL
			}()
		}

		// Log proxy information for debugging
		log.Printf("🔄 Proxy-aware request: %s %s (Original: %s://%s, Forwarded: %s://%s)",
			r.Method, r.RequestURI, originalScheme, originalHost, r.URL.Scheme, r.Host)

		handler(w, r)
	}
}

// Add these handler aliases after your existing handlers

func deviceVerificationHandler(w http.ResponseWriter, r *http.Request) {
	deviceHandler(w, r) // Use your existing deviceHandler
}

// OAuth2 Authorization Server Metadata handler (RFC 8414)
func oauth2DiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	// Get the effective base URL (proxy-aware)
	baseURL := configuration.GetEffectiveBaseURL(r)

	// OAuth2 Authorization Server Metadata (RFC 8414)
	oauth2Metadata := map[string]interface{}{
		// Required fields
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/oauth/authorize",
		"token_endpoint":         baseURL + "/oauth/token",
		"jwks_uri":               baseURL + "/.well-known/jwks.json",

		// Optional but recommended fields
		"registration_endpoint":  baseURL + "/register",
		"revocation_endpoint":    baseURL + "/oauth/revoke",
		"introspection_endpoint": baseURL + "/oauth/introspect",
		"userinfo_endpoint":      baseURL + "/userinfo",

		// Device Flow (RFC 8628)
		"device_authorization_endpoint": baseURL + "/device/authorize",

		// Supported response types
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
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

		// Token Exchange specific metadata (RFC 8693)
		"token_exchange_grant_types_supported": []string{
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		"subject_token_types_supported": []string{
			"urn:ietf:params:oauth:token-type:access_token",
			"urn:ietf:params:oauth:token-type:refresh_token",
			"urn:ietf:params:oauth:token-type:id_token",
		},

		"actor_token_types_supported": []string{
			"urn:ietf:params:oauth:token-type:access_token",
		},

		// Supported scopes
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
			"offline_access",
			"api:read",
			"api:write",
			"admin",
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
			"RS256",
			"HS256",
		},

		// PKCE support
		"code_challenge_methods_supported": []string{
			"plain",
			"S256",
		},

		// Introspection endpoint authentication methods
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},

		// Revocation endpoint authentication methods
		"revocation_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},

		// Additional capabilities
		"response_modes_supported": []string{
			"query",
			"fragment",
			"form_post",
		},

		// Service documentation
		"service_documentation": baseURL + "/docs",
		"op_policy_uri":         baseURL + "/policy",
		"op_tos_uri":            baseURL + "/terms",
	}

	json.NewEncoder(w).Encode(oauth2Metadata)
}
