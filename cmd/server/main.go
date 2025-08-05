package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	mathrand "math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"oauth2-demo/internal/config"
	"oauth2-demo/internal/storage"
)

// Global variables
var (
	log       = logrus.New()
	appConfig *config.Config
	templates *template.Template
	store     storage.Storage
)

// OAuth2 request/response structures
type AuthorizeRequest = storage.AuthorizeRequest
type DeviceCodeResponse = storage.DeviceCodeResponse
type DeviceCodeState = storage.DeviceCodeState

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	Scope        string `json:"scope,omitempty"`
	// Token Exchange fields
	SubjectToken       string `json:"subject_token,omitempty"`
	SubjectTokenType   string `json:"subject_token_type,omitempty"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
	// Device flow fields
	DeviceCode string `json:"device_code,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ClientRegistrationRequest represents a dynamic client registration request (RFC 7591)
type ClientRegistrationRequest struct {
	RedirectURIs            []string    `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string    `json:"grant_types,omitempty"`
	ResponseTypes           []string    `json:"response_types,omitempty"`
	ClientName              string      `json:"client_name,omitempty"`
	ClientURI               string      `json:"client_uri,omitempty"`
	LogoURI                 string      `json:"logo_uri,omitempty"`
	Scope                   string      `json:"scope,omitempty"`
	Contacts                []string    `json:"contacts,omitempty"`
	TosURI                  string      `json:"tos_uri,omitempty"`
	PolicyURI               string      `json:"policy_uri,omitempty"`
	JwksURI                 string      `json:"jwks_uri,omitempty"`
	Jwks                    interface{} `json:"jwks,omitempty"`
	SoftwareID              string      `json:"software_id,omitempty"`
	SoftwareVersion         string      `json:"software_version,omitempty"`
}

// ClientRegistrationResponse represents a dynamic client registration response (RFC 7591)
type ClientRegistrationResponse struct {
	ClientID                string      `json:"client_id"`
	ClientSecret            string      `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64       `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64       `json:"client_secret_expires_at"`
	RedirectURIs            []string    `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string    `json:"grant_types,omitempty"`
	ResponseTypes           []string    `json:"response_types,omitempty"`
	ClientName              string      `json:"client_name,omitempty"`
	ClientURI               string      `json:"client_uri,omitempty"`
	LogoURI                 string      `json:"logo_uri,omitempty"`
	Scope                   string      `json:"scope,omitempty"`
	Contacts                []string    `json:"contacts,omitempty"`
	TosURI                  string      `json:"tos_uri,omitempty"`
	PolicyURI               string      `json:"policy_uri,omitempty"`
	JwksURI                 string      `json:"jwks_uri,omitempty"`
	Jwks                    interface{} `json:"jwks,omitempty"`
	SoftwareID              string      `json:"software_id,omitempty"`
	SoftwareVersion         string      `json:"software_version,omitempty"`
	RegistrationAccessToken string      `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string      `json:"registration_client_uri,omitempty"`
}

func main() {
	log.Println("🚀 Starting OAuth2 Server...")

	// Load configuration
	var err error
	appConfig, err = config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// Initialize storage
	store, err = storage.NewStorage(&appConfig.Database)
	if err != nil {
		log.Fatalf("❌ Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// Initialize logger
	initializeLogger()

	// Load templates
	if err := loadTemplates(); err != nil {
		log.Fatalf("❌ Failed to load templates: %v", err)
	}

	log.Info("✅ OAuth2 server initialized with persistent storage")

	// Start cleanup routine
	go startCleanupRoutine()

	// Setup HTTP routes
	setupRoutes()

	// Start server with graceful shutdown
	startServer()
}

func initializeLogger() {
	switch strings.ToLower(appConfig.Logging.Level) {
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

	if appConfig.Logging.Format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{})
	}
}

func startCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute) // Clean every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		if err := store.CleanupExpired(); err != nil {
			log.WithError(err).Error("Failed to cleanup expired entries")
		}
	}
}

func loadTemplates() error {
	templatesDir := "templates"

	// Check if templates directory exists
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		return fmt.Errorf("templates directory not found: %s", templatesDir)
	}

	var err error
	templates, err = template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}

	return nil
}

func setupRoutes() {
	// OAuth2 endpoints
	http.HandleFunc("/oauth2/auth", handleAuthorize)
	http.HandleFunc("/oauth2/token", handleToken)
	http.HandleFunc("/oauth2/introspect", handleIntrospect)

	// Dynamic Client Registration (RFC 7591)
	http.HandleFunc("/oauth2/register", handleClientRegistration)

	// Device flow endpoints
	http.HandleFunc("/device/code", handleDeviceAuth)
	http.HandleFunc("/device/verify", handleDeviceVerify)
	http.HandleFunc("/device/authorize", handleDeviceAuthorize)
	http.HandleFunc("/device/poll", handleDevicePoll)

	// Discovery endpoints
	http.HandleFunc("/.well-known/oauth-authorization-server", handleOAuthDiscovery)
	http.HandleFunc("/.well-known/openid-configuration", handleOpenIDDiscovery)
	http.HandleFunc("/.well-known/jwks.json", handleJWKS)

	// Authentication endpoints
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/auth/consent", handleConsent)

	// Static files and root
	http.HandleFunc("/", handleRoot)

	log.Info("✅ HTTP routes configured")
}

func startServer() {
	addr := fmt.Sprintf("%s:%d", appConfig.Server.Host, appConfig.Server.Port)

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  time.Duration(appConfig.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(appConfig.Server.WriteTimeout) * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Infof("🌐 Server starting on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("🛑 Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(appConfig.Server.ShutdownTimeout)*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("❌ Server forced to shutdown: %v", err)
	}

	log.Info("✅ Server stopped")
}

// OAuth2 Authorization endpoint
func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse authorization request
	req := &AuthorizeRequest{
		ClientID:            r.URL.Query().Get("client_id"),
		ResponseType:        r.URL.Query().Get("response_type"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}

	// Basic validation
	if req.ClientID == "" || req.ResponseType == "" {
		writeError(w, "invalid_request", "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Validate client
	client := findClient(req.ClientID)
	if client == nil {
		writeError(w, "invalid_client", "Unknown client", http.StatusBadRequest)
		return
	}

	// Check if user is authenticated
	if !isUserAuthenticated(r) {
		// Show login form with authorization context
		showLoginForm(w, r, req)
		return
	}

	// Generate authorization code
	code := generateRandomString(32)
	if err := store.StoreAuthCode(code, req); err != nil {
		log.WithError(err).Error("Failed to store authorization code")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Redirect with authorization code
	redirectURI := req.RedirectURI + "?code=" + code
	if req.State != "" {
		redirectURI += "&state=" + req.State
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// OAuth2 Token endpoint
func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		handleAuthorizationCodeGrant(w, r)
	case "client_credentials":
		handleClientCredentialsGrant(w, r)
	case "refresh_token":
		handleRefreshTokenGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		handleTokenExchangeGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		handleDeviceCodeGrant(w, r)
	default:
		writeError(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
	}
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")

	// Validate authorization code
	authReq, err := store.GetAuthCode(code)
	if err != nil || authReq == nil || authReq.ClientID != clientID {
		writeError(w, "invalid_grant", "Invalid authorization code", http.StatusBadRequest)
		return
	}

	// Generate tokens
	accessToken := generateRandomString(64)
	refreshToken := generateRandomString(64)

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    appConfig.Security.TokenExpirySeconds,
		RefreshToken: refreshToken,
		Scope:        authReq.Scope,
	}

	// Clean up authorization code
	if err := store.DeleteAuthCode(code); err != nil {
		log.WithError(err).Error("Failed to delete authorization code")
		// Continue - token response is valid even if cleanup fails
	}

	writeTokenResponse(w, response)
}

func handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// Basic client authentication
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	// Validate client credentials
	client := findClient(clientID)
	if client == nil || client.Secret != clientSecret {
		writeError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Generate access token
	accessToken := generateRandomString(64)

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   appConfig.Security.TokenExpirySeconds,
		Scope:       r.FormValue("scope"),
	}

	writeTokenResponse(w, response)
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement refresh token grant
	writeError(w, "unsupported_grant_type", "Refresh token grant not implemented", http.StatusNotImplemented)
}

func handleTokenExchangeGrant(w http.ResponseWriter, r *http.Request) {
	// RFC 8693 Token Exchange implementation
	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")
	requestedTokenType := r.FormValue("requested_token_type")

	if subjectToken == "" || subjectTokenType == "" {
		writeError(w, "invalid_request", "Missing required token exchange parameters", http.StatusBadRequest)
		return
	}

	// For demo purposes, generate a new token
	// In a real implementation, you would validate the subject token
	newToken := generateRandomString(64)

	response := TokenResponse{
		AccessToken: newToken,
		TokenType:   "Bearer",
		ExpiresIn:   appConfig.Security.TokenExpirySeconds,
		Scope:       "exchanged",
	}

	log.Infof("Token exchange: %s -> %s", subjectTokenType, requestedTokenType)
	writeTokenResponse(w, response)
}

func handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")
	clientID := r.FormValue("client_id")

	// Basic client authentication (optional for public clients)
	if clientID == "" {
		clientID, _, _ = r.BasicAuth()
	}

	if deviceCode == "" {
		writeError(w, "invalid_request", "Missing device_code parameter", http.StatusBadRequest)
		return
	}

	// Check if device code exists
	deviceState, err := store.GetDeviceCode(deviceCode)
	if err != nil || deviceState == nil {
		writeError(w, "invalid_grant", "Invalid device code", http.StatusBadRequest)
		return
	}

	// Validate client ID if provided
	if clientID != "" && deviceState.ClientID != clientID {
		writeError(w, "invalid_client", "Client ID mismatch", http.StatusBadRequest)
		return
	}

	// Check if device code has expired
	if time.Since(deviceState.CreatedAt) > time.Duration(deviceState.ExpiresIn)*time.Second {
		store.DeleteDeviceCode(deviceCode) // Don't check error for expired cleanup
		writeError(w, "expired_token", "Device code has expired", http.StatusBadRequest)
		return
	}

	// Check authorization status
	if !deviceState.Authorized {
		// Still pending user authorization
		writeError(w, "authorization_pending", "User hasn't authorized the device yet", http.StatusBadRequest)
		return
	}

	// Device is authorized, return access token
	response := TokenResponse{
		AccessToken: deviceState.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   appConfig.Security.TokenExpirySeconds,
		Scope:       deviceState.Scope,
	}

	// Clean up device code (one-time use)
	if err := store.DeleteDeviceCode(deviceCode); err != nil {
		log.WithError(err).Error("Failed to delete device code after successful grant")
		// Continue - token response is valid even if cleanup fails
	}

	log.Infof("Device code grant completed for client %s", deviceState.ClientID)
	writeTokenResponse(w, response)
}

// Token introspection endpoint
func handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"active": false}`)
}

// OAuth2 Authorization Server Discovery (RFC 8414)
func handleOAuthDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseURL := appConfig.Server.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%d", appConfig.Server.Host, appConfig.Server.Port)
	}

	discovery := map[string]interface{}{
		"issuer":                        baseURL,
		"authorization_endpoint":        baseURL + "/oauth2/auth",
		"token_endpoint":                baseURL + "/oauth2/token",
		"introspection_endpoint":        baseURL + "/oauth2/introspect",
		"device_authorization_endpoint": baseURL + "/device/code",
		"jwks_uri":                      baseURL + "/.well-known/jwks.json",
		"response_types_supported":      []string{"code", "token"},
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},
		"token_endpoint_auth_methods_supported":            []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                                 []string{"openid", "profile", "email", "offline_access"},
		"code_challenge_methods_supported":                 []string{"S256", "plain"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "HS256"},
	}

	// Add dynamic registration endpoint if enabled
	if appConfig.Security.DynamicRegistration.Enabled {
		discovery["registration_endpoint"] = baseURL + "/oauth2/register"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(discovery)
}

// OpenID Connect Discovery (RFC 7517)
func handleOpenIDDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseURL := appConfig.Server.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%d", appConfig.Server.Host, appConfig.Server.Port)
	}

	discovery := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth2/auth",
		"token_endpoint":                        baseURL + "/oauth2/token",
		"userinfo_endpoint":                     baseURL + "/userinfo",
		"introspection_endpoint":                baseURL + "/oauth2/introspect",
		"device_authorization_endpoint":         baseURL + "/device/code",
		"jwks_uri":                              baseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "id_token", "token", "code id_token", "code token", "id_token token", "code id_token token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "HS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "email_verified", "preferred_username"},
		"grant_types_supported": []string{
			"authorization_code",
			"implicit",
			"refresh_token",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},
		"code_challenge_methods_supported": []string{"S256", "plain"},
	}

	// Add dynamic registration endpoint if enabled
	if appConfig.Security.DynamicRegistration.Enabled {
		discovery["registration_endpoint"] = baseURL + "/oauth2/register"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(discovery)
}

// JSON Web Key Set endpoint (RFC 7517)
func handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// For demonstration purposes, we'll return a basic JWK set
	// In production, you should use actual RSA/ECDSA keys for JWT signing
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "oct", // Symmetric key for HMAC (demo only)
				"use": "sig",
				"alg": "HS256",
				"kid": "demo-key-1",
				// Note: In production, don't expose symmetric keys in JWKS
				// This is for demonstration only
			},
			{
				"kty": "RSA", // Example RSA key structure (would need actual values)
				"use": "sig",
				"alg": "RS256",
				"kid": "demo-rsa-key-1",
				"n":   "placeholder-for-rsa-modulus",
				"e":   "AQAB",
				// Note: In production, include actual RSA public key components
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(jwks)
}

// Dynamic Client Registration endpoint (RFC 7591)
func handleClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if dynamic registration is enabled
	if !appConfig.Security.DynamicRegistration.Enabled {
		writeError(w, "invalid_request", "Dynamic client registration is not enabled", http.StatusForbidden)
		return
	}

	// Check for initial access token if required
	if appConfig.Security.DynamicRegistration.RequireInitialAccessToken {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, "invalid_client_metadata", "Initial access token required", http.StatusUnauthorized)
			return
		}

		// Extract Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeError(w, "invalid_client_metadata", "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		// Validate initial access token
		if parts[1] != appConfig.Security.DynamicRegistration.InitialAccessToken {
			writeError(w, "invalid_client_metadata", "Invalid initial access token", http.StatusUnauthorized)
			return
		}
	}

	// Parse registration request
	var regReq ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&regReq); err != nil {
		writeError(w, "invalid_client_metadata", "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate and process registration request
	client, err := processClientRegistration(&regReq)
	if err != nil {
		writeError(w, "invalid_client_metadata", err.Error(), http.StatusBadRequest)
		return
	}

	// Store the dynamically registered client
	if err := store.StoreDynamicClient(client.ID, client); err != nil {
		log.WithError(err).Error("Failed to store dynamic client")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate registration access token
	registrationToken := generateRandomString(64)
	if err := store.StoreRegistrationToken(registrationToken, client.ID); err != nil {
		log.WithError(err).Error("Failed to store registration token")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build registration response
	baseURL := appConfig.Server.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%d", appConfig.Server.Host, appConfig.Server.Port)
	}

	response := ClientRegistrationResponse{
		ClientID:                client.ID,
		ClientSecret:            client.Secret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   calculateClientSecretExpiry(),
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ClientName:              client.Name,
		Scope:                   strings.Join(client.Scopes, " "),
		RegistrationAccessToken: registrationToken,
		RegistrationClientURI:   baseURL + "/oauth2/register/" + client.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	log.Infof("Dynamic client registered: %s (%s)", client.ID, client.Name)
}

// Device authorization endpoint (RFC 8628)
func handleDeviceAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	// Validate client
	client := findClient(clientID)
	if client == nil {
		writeError(w, "invalid_client", "Unknown client", http.StatusBadRequest)
		return
	}

	// Generate device and user codes
	deviceCode := generateRandomString(32)
	userCode := generateUserCode()

	baseURL := appConfig.Server.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%d", appConfig.Server.Host, appConfig.Server.Port)
	}
	verificationURI := baseURL + "/device/verify"
	verificationURIComplete := verificationURI + "?user_code=" + userCode

	response := DeviceCodeResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               appConfig.Security.DeviceCodeExpirySeconds,
		Interval:                5,
	}

	// Store device code state
	deviceState := &DeviceCodeState{
		DeviceCodeResponse: &response,
		ClientID:           clientID,
		Scope:              scope,
		CreatedAt:          time.Now(),
		Authorized:         false,
	}
	if err := store.StoreDeviceCode(deviceCode, deviceState); err != nil {
		log.WithError(err).Error("Failed to store device code")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Device verification page
func handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Show device verification form
		userCode := r.URL.Query().Get("user_code")
		data := map[string]interface{}{
			"Title":    "Device Verification",
			"UserCode": userCode,
		}

		if err := templates.ExecuteTemplate(w, "device_verify.html", data); err != nil {
			log.Errorf("Failed to execute template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		// Handle device verification
		userCode := r.FormValue("user_code")

		// Find device code by user code
		foundDeviceState, foundDeviceCode, err := store.GetDeviceCodeByUserCode(userCode)
		if err != nil {
			log.WithError(err).Error("Failed to lookup device code by user code")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if foundDeviceState == nil {
			data := map[string]interface{}{
				"Title": "Device Verification",
				"Error": "Invalid user code",
			}
			templates.ExecuteTemplate(w, "device_verify.html", data)
			return
		}

		// Check if device code has expired
		if time.Since(foundDeviceState.CreatedAt) > time.Duration(foundDeviceState.ExpiresIn)*time.Second {
			data := map[string]interface{}{
				"Title": "Device Verification",
				"Error": "User code has expired",
			}
			templates.ExecuteTemplate(w, "device_verify.html", data)
			return
		}

		// Check if user is authenticated
		if !isUserAuthenticated(r) {
			// Store the device verification context and redirect to login
			data := map[string]interface{}{
				"Title":        "Login Required",
				"UserCode":     userCode,
				"DeviceCode":   foundDeviceCode,
				"ClientName":   getClientName(foundDeviceState.ClientID),
				"Scope":        foundDeviceState.Scope,
				"Scopes":       strings.Split(foundDeviceState.Scope, " "),
				"IsDeviceFlow": true,
			}

			if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
				log.Errorf("Failed to execute template: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		// User is authenticated, now show consent/authorization screen
		user := getUserFromSession(r)
		if user == nil {
			data := map[string]interface{}{
				"Title": "Device Verification",
				"Error": "Authentication session invalid",
			}
			templates.ExecuteTemplate(w, "device_verify.html", data)
			return
		}

		// Show device authorization consent screen
		data := map[string]interface{}{
			"Title":      "Authorize Device",
			"UserCode":   userCode,
			"DeviceCode": foundDeviceCode,
			"User":       user,
			"Client": map[string]interface{}{
				"Name": getClientName(foundDeviceState.ClientID),
				"ID":   foundDeviceState.ClientID,
			},
			"Scope":  foundDeviceState.Scope,
			"Scopes": strings.Split(foundDeviceState.Scope, " "),
		}

		if err := templates.ExecuteTemplate(w, "device_consent.html", data); err != nil {
			log.Errorf("Failed to execute template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
}

// Device authorization endpoint - handles final user authorization
func handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userCode := r.FormValue("user_code")
	deviceCode := r.FormValue("device_code")
	action := r.FormValue("action") // "authorize" or "deny"

	// Find device code state
	foundDeviceState, err := store.GetDeviceCode(deviceCode)
	if err != nil || foundDeviceState == nil || foundDeviceState.UserCode != userCode {
		writeError(w, "invalid_request", "Invalid device or user code", http.StatusBadRequest)
		return
	}

	// Check if device code has expired
	if time.Since(foundDeviceState.CreatedAt) > time.Duration(foundDeviceState.ExpiresIn)*time.Second {
		writeError(w, "invalid_request", "Device code has expired", http.StatusBadRequest)
		return
	}

	// Check if user is authenticated
	user := getUserFromSession(r)
	if user == nil {
		writeError(w, "access_denied", "User not authenticated", http.StatusUnauthorized)
		return
	}

	if action == "authorize" {
		// User authorized the device
		foundDeviceState.Authorized = true
		foundDeviceState.UserID = user.ID

		// Generate access token
		accessToken := generateRandomString(64)
		foundDeviceState.AccessToken = accessToken

		// Update the device state in storage
		if err := store.UpdateDeviceCode(deviceCode, foundDeviceState); err != nil {
			log.WithError(err).Error("Failed to update device code state")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		log.Infof("Device authorized by user %s for client %s", user.Username, foundDeviceState.ClientID)

		// Show success page
		data := map[string]interface{}{
			"Title":   "Device Authorized",
			"Message": "Your device has been successfully authorized. You can now close this window and return to your device.",
		}

		if err := templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
			log.Errorf("Failed to execute template: %v", err)
			fmt.Fprintf(w, "Device authorized successfully! You can close this window.")
		}

	} else if action == "deny" {
		// User denied the device authorization
		if err := store.DeleteDeviceCode(deviceCode); err != nil {
			log.WithError(err).Error("Failed to delete device code after denial")
			// Continue - denial is still processed
		}

		log.Infof("Device authorization denied by user %s for client %s", user.Username, foundDeviceState.ClientID)

		// Show denial page
		data := map[string]interface{}{
			"Title":   "Device Access Denied",
			"Message": "You have denied access to your device. You can close this window.",
		}

		if err := templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
			log.Errorf("Failed to execute template: %v", err)
			fmt.Fprintf(w, "Device access denied. You can close this window.")
		}

	} else {
		writeError(w, "invalid_request", "Invalid action", http.StatusBadRequest)
	}
}

// Device polling endpoint
func handleDevicePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DeviceCode string `json:"device_code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if device code exists
	deviceState, err := store.GetDeviceCode(req.DeviceCode)
	if err != nil || deviceState == nil {
		writeError(w, "invalid_grant", "Invalid device code", http.StatusBadRequest)
		return
	}

	// Check if device code has expired
	if time.Since(deviceState.CreatedAt) > time.Duration(deviceState.ExpiresIn)*time.Second {
		store.DeleteDeviceCode(req.DeviceCode) // Don't check error for expired cleanup
		writeError(w, "expired_token", "Device code has expired", http.StatusBadRequest)
		return
	}

	// Check authorization status
	if !deviceState.Authorized {
		// Still pending user authorization
		writeError(w, "authorization_pending", "Authorization pending", http.StatusBadRequest)
		return
	}

	// Device is authorized, return access token
	response := TokenResponse{
		AccessToken: deviceState.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   appConfig.Security.TokenExpirySeconds,
		Scope:       deviceState.Scope,
	}

	// Clean up device code (one-time use)
	if err := store.DeleteDeviceCode(req.DeviceCode); err != nil {
		log.WithError(err).Error("Failed to delete device code after successful authorization")
		// Continue - token response is valid even if cleanup fails
	}

	log.Infof("Device code flow completed for client %s", deviceState.ClientID)
	writeTokenResponse(w, response)
}

// Login handler
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Show login form
		showLoginForm(w, r, nil)
		return
	}

	if r.Method == http.MethodPost {
		// Process login
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Check if this is part of device flow
		userCode := r.FormValue("user_code")
		deviceCode := r.FormValue("device_code")

		// Authenticate user
		user := authenticateUser(username, password)
		if user == nil {
			if userCode != "" && deviceCode != "" {
				// Device flow login failed
				data := map[string]interface{}{
					"Title":        "Login Required",
					"Error":        "Invalid username or password",
					"UserCode":     userCode,
					"DeviceCode":   deviceCode,
					"IsDeviceFlow": true,
				}
				templates.ExecuteTemplate(w, "login.html", data)
				return
			}
			showLoginForm(w, r, nil, "Invalid username or password")
			return
		}

		// Set session cookie
		setUserSession(w, user)

		// Check if this is device flow
		if userCode != "" && deviceCode != "" {
			// Redirect back to device verification with session
			http.Redirect(w, r, fmt.Sprintf("/device/verify?user_code=%s", userCode), http.StatusFound)
			return
		}

		// Check if this is an OAuth2 flow
		if state := r.FormValue("state"); state != "" {
			// Redirect back to authorization endpoint with original parameters
			originalURL := r.Referer()
			if originalURL != "" {
				http.Redirect(w, r, originalURL, http.StatusFound)
				return
			}
		}

		// Regular login success
		fmt.Fprintf(w, "Login successful! Welcome, %s", user.Name)
		return
	}

	writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
}

// Consent handler
func handleConsent(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Consent screen - TODO")
}

// Root handler
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>OAuth2 Server</title>
		<style>
			body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
			.endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
			.method { font-weight: bold; color: #0066cc; }
			.status { background: #e8f5e8; padding: 10px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #4caf50; }
		</style>
	</head>
	<body>
		<h1>🔐 OAuth2 Server</h1>
		<p>OAuth2 Server with RFC 8693 Token Exchange and RFC 8628 Device Authorization Grant support.</p>
		
		<div class="status">
			<strong>✅ Status:</strong> Server running with local Fosite fork support<br>
			<strong>📁 Local Fork:</strong> ./fosite directory contains RFC 8693 implementation
		</div>
		
		<h2>Available Endpoints:</h2>
		<div class="endpoint">
			<div class="method">GET</div>
			<strong>/oauth2/auth</strong> - Authorization endpoint
		</div>
		<div class="endpoint">
			<div class="method">POST</div>
			<strong>/oauth2/token</strong> - Token endpoint (supports Token Exchange)
		</div>
		<div class="endpoint">
			<div class="method">POST</div>
			<strong>/oauth2/introspect</strong> - Token introspection
		</div>
		<div class="endpoint">
			<div class="method">POST</div>
			<strong>/oauth2/register</strong> - Dynamic Client Registration (RFC 7591)
		</div>
		<div class="endpoint">
			<div class="method">GET</div>
			<strong>/.well-known/oauth-authorization-server</strong> - OAuth2 Server Discovery (RFC 8414)
		</div>
		<div class="endpoint">
			<div class="method">GET</div>
			<strong>/.well-known/openid-configuration</strong> - OpenID Connect Discovery
		</div>
		<div class="endpoint">
			<div class="method">GET</div>
			<strong>/.well-known/jwks.json</strong> - JSON Web Key Set (RFC 7517)
		</div>
		<div class="endpoint">
			<div class="method">POST</div>
			<strong>/device/code</strong> - Device authorization (RFC 8628)
		</div>
		<div class="endpoint">
			<div class="method">GET/POST</div>
			<strong>/device/verify</strong> - Device verification
		</div>
		<div class="endpoint">
			<div class="method">GET/POST</div>
			<strong>/login</strong> - User login
		</div>
		
		<h2>Configuration:</h2>
		<ul>
			<li>Server: %s:%d</li>
			<li>Clients: %d configured</li>
			<li>Users: %d configured</li>
			<li>Local Fosite Fork: ✅ Available in ./fosite</li>
		</ul>
		
		<h2>Next Steps:</h2>
		<ul>
			<li>✅ Basic OAuth2 server structure implemented</li>
			<li>✅ Configuration loading from YAML</li>
			<li>✅ HTML templates for authentication</li>
			<li>🔧 To enable full Fosite integration: uncomment replace directive in go.mod</li>
			<li>🔧 Run: <code>go mod tidy && go run cmd/server/main.go</code></li>
		</ul>
	</body>
	</html>`

	fmt.Fprintf(w, html,
		appConfig.Server.Host,
		appConfig.Server.Port,
		len(appConfig.Clients),
		len(appConfig.Users))
}

// Helper functions

func showLoginForm(w http.ResponseWriter, r *http.Request, authReq *AuthorizeRequest, errors ...string) {
	data := map[string]interface{}{
		"Title": "Login",
	}

	if len(errors) > 0 {
		data["Error"] = errors[0]
	}

	if authReq != nil {
		data["ClientID"] = authReq.ClientID
		data["State"] = authReq.State
		data["Scope"] = authReq.Scope
		data["ResponseType"] = authReq.ResponseType
		data["RedirectURI"] = authReq.RedirectURI

		// Get client info
		if client := findClient(authReq.ClientID); client != nil {
			data["Client"] = map[string]interface{}{
				"ID":   client.ID,
				"Name": client.Name,
			}
		}

		if authReq.Scope != "" {
			data["Scopes"] = strings.Split(authReq.Scope, " ")
		}
	}

	if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Errorf("Failed to execute template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func isUserAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("user_session")
	if err != nil {
		return false
	}
	return cookie.Value != ""
}

func setUserSession(w http.ResponseWriter, user *config.UserConfig) {
	sessionToken := base64.URLEncoding.EncodeToString([]byte(user.Username + ":" + user.ID))
	cookie := &http.Cookie{
		Name:     "user_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   appConfig.Security.RequireHTTPS,
		MaxAge:   3600,
	}
	http.SetCookie(w, cookie)
}

func findClient(clientID string) *config.ClientConfig {
	// First check static clients from config
	for _, client := range appConfig.Clients {
		if client.ID == clientID {
			return &client
		}
	}

	// Then check dynamically registered clients
	if client, err := store.GetDynamicClient(clientID); err == nil && client != nil {
		return client
	}

	return nil
}

func authenticateUser(username, password string) *config.UserConfig {
	for _, user := range appConfig.Users {
		if user.Username == username && user.Password == password && user.Enabled {
			return &user
		}
	}
	return nil
}

func getClientName(clientID string) string {
	client := findClient(clientID)
	if client != nil && client.Name != "" {
		return client.Name
	}
	return clientID // Fallback to client ID if no name
}

func getUserFromSession(r *http.Request) *config.UserConfig {
	cookie, err := r.Cookie("user_session")
	if err != nil {
		return nil
	}

	// Decode session token
	sessionData, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil
	}

	// Parse username from session (format: "username:userID")
	parts := strings.Split(string(sessionData), ":")
	if len(parts) != 2 {
		return nil
	}

	username := parts[0]

	// Find user by username
	for _, user := range appConfig.Users {
		if user.Username == username && user.Enabled {
			return &user
		}
	}
	return nil
}

func processClientRegistration(regReq *ClientRegistrationRequest) (*config.ClientConfig, error) {
	// Generate client ID and secret
	clientID := generateRandomString(32)
	clientSecret := generateRandomString(64)

	// Set default values
	if len(regReq.GrantTypes) == 0 {
		regReq.GrantTypes = []string{"authorization_code"}
	}

	if len(regReq.ResponseTypes) == 0 {
		regReq.ResponseTypes = []string{"code"}
	}

	if regReq.TokenEndpointAuthMethod == "" {
		regReq.TokenEndpointAuthMethod = "client_secret_basic"
	}

	// Validate grant types against allowed ones
	allowedGrantTypes := appConfig.Security.DynamicRegistration.AllowedGrantTypes
	if len(allowedGrantTypes) > 0 {
		for _, grantType := range regReq.GrantTypes {
			if !contains(allowedGrantTypes, grantType) {
				return nil, fmt.Errorf("grant type %s is not allowed", grantType)
			}
		}
	}

	// Validate response types against allowed ones
	allowedResponseTypes := appConfig.Security.DynamicRegistration.AllowedResponseTypes
	if len(allowedResponseTypes) > 0 {
		for _, responseType := range regReq.ResponseTypes {
			if !contains(allowedResponseTypes, responseType) {
				return nil, fmt.Errorf("response type %s is not allowed", responseType)
			}
		}
	}

	// Validate redirect URIs - only required for flows that use the authorization endpoint
	requiresRedirectURI := false

	// Check if any grant types require redirect URIs
	for _, grantType := range regReq.GrantTypes {
		// Grant types that require redirect URIs (flows that use authorization endpoint)
		if grantType == "authorization_code" || grantType == "implicit" {
			requiresRedirectURI = true
			break
		}
	}

	// Only check response types if we already have grant types that use authorization endpoint
	if requiresRedirectURI {
		for _, responseType := range regReq.ResponseTypes {
			// Response types that require redirect URIs
			if responseType == "code" || responseType == "token" || responseType == "id_token" {
				requiresRedirectURI = true
				break
			}
		}
	}

	// Apply redirect URI requirement logic
	if requiresRedirectURI && len(regReq.RedirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris is required for grant types that use redirects")
	}

	// Also check global config requirement (if admin wants to always require redirect URIs)
	if appConfig.Security.DynamicRegistration.RequireRedirectURI && len(regReq.RedirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris is required by server policy")
	}

	// Parse and validate scopes
	var scopes []string
	if regReq.Scope != "" {
		scopes = strings.Fields(regReq.Scope)
		allowedScopes := appConfig.Security.DynamicRegistration.AllowedScopes
		if len(allowedScopes) > 0 {
			for _, scope := range scopes {
				if !contains(allowedScopes, scope) {
					return nil, fmt.Errorf("scope %s is not allowed", scope)
				}
			}
		}
	}

	// Create client configuration
	client := &config.ClientConfig{
		ID:                      clientID,
		Secret:                  clientSecret,
		Name:                    regReq.ClientName,
		RedirectURIs:            regReq.RedirectURIs,
		GrantTypes:              regReq.GrantTypes,
		ResponseTypes:           regReq.ResponseTypes,
		Scopes:                  scopes,
		TokenEndpointAuthMethod: regReq.TokenEndpointAuthMethod,
		Public:                  regReq.TokenEndpointAuthMethod == "none",
	}

	return client, nil
}

func calculateClientSecretExpiry() int64 {
	if appConfig.Security.DynamicRegistration.ClientSecretExpirySeconds > 0 {
		return time.Now().Add(time.Duration(appConfig.Security.DynamicRegistration.ClientSecretExpirySeconds) * time.Second).Unix()
	}
	return 0 // Never expires
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func generateUserCode() string {
	// Generate a user-friendly code like "ABCD-EFGH"
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 8)
	for i := range code {
		code[i] = chars[mathrand.Intn(len(chars))]
	}
	return string(code[:4]) + "-" + string(code[4:])
}

func writeTokenResponse(w http.ResponseWriter, response TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

func writeError(w http.ResponseWriter, error, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:            error,
		ErrorDescription: description,
	})
}
