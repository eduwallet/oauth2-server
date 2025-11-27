package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"flag"

	"html/template"
	"os"
	"path/filepath"

	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/sirupsen/logrus"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"oauth2-server/internal/attestation"
	"oauth2-server/internal/auth"
	"oauth2-server/internal/handlers"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/middleware"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// Version information - set during build
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// Create a logger instance
var log = logrus.New()

var (
	// Application configuration
	configuration *config.Config

	// OAuth2 provider and stores
	oauth2Provider fosite.OAuth2Provider
	dataStore      store.Storage        // Use our custom storage interface
	customStorage  *store.CustomStorage // Custom storage wrapper

	// TokenStrategy
	AccessTokenStrategy  oauth2.AccessTokenStrategy
	RefreshTokenStrategy oauth2.RefreshTokenStrategy

	// Handlers
	registrationHandler               *handlers.RegistrationHandler
	deviceCodeHandler                 *handlers.DeviceCodeHandler
	introspectionHandler              *handlers.IntrospectionHandler
	authorizationIntrospectionHandler *handlers.AuthorizationIntrospectionHandler
	discoveryHandler                  *handlers.DiscoveryHandler
	statusHandler                     *handlers.StatusHandler
	tokenHandler                      *handlers.TokenHandler
	revokeHandler                     *handlers.RevokeHandler
	jwksHandler                       *handlers.JWKSHandler
	healthHandler                     *handlers.HealthHandler
	oauth2DiscoveryHandler            *handlers.OAuth2DiscoveryHandler
	authorizeHandler                  *handlers.AuthorizeHandler
	claimsHandler                     *handlers.ClaimsHandler
	versionHandler                    *handlers.VersionHandler
	userinfoHandler                   *handlers.UserInfoHandler
	callbackHandler                   *handlers.CallbackHandler
	trustAnchorHandler                *handlers.TrustAnchorHandler

	// Secret manager for encrypted storage
	secretManager *store.SecretManager

	// Metrics collector
	metricsCollector *metrics.MetricsCollector

	// Attestation manager
	attestationManager *attestation.VerifierManager

	// Templates
	templates *template.Template
)

// Maps for persisting original authorization state through the OAuth2 flow in proxy mode
var authCodeToStateMap = make(map[string]string)          // authorization_code -> original_state
var deviceCodeToUpstreamMap = make(map[string]string)     // proxy_device_code -> upstream_device_code
var accessTokenToIssuerStateMap = make(map[string]string) // access_token -> issuer_state
var UpstreamSessionMap = make(map[string]handlers.UpstreamSessionData)

// Map to store plain text secrets for privileged clients
var privilegedClientSecrets = make(map[string]string)

func main() {
	// Handle version flag
	var showVersion = flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("OAuth2 Server\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		fmt.Printf("Build Time: %s\n", BuildTime)
		return
	}

	log.Printf("🚀 Starting OAuth2 Server v%s (commit: %s)", Version, GitCommit)

	log.Printf("DEBUG: UPSTREAM_PROVIDER_URL: %s", os.Getenv("UPSTREAM_PROVIDER_URL"))

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
	logLevel := configuration.Logging.Level
	logFormat := configuration.Logging.Format
	enableAudit := configuration.Logging.EnableAudit

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

	log.Info("✅ Configuration loaded successfully")
	log.Infof("🔧 Log Level: %s, Format: %s, Audit: %t", logLevel, logFormat, enableAudit)
	log.Infof("🔧 Privileged Client ID: %s", configuration.Security.PrivilegedClientID)

	// Initialize secret manager for encrypted storage
	secretManager = store.NewSecretManager([]byte(configuration.Security.EncryptionKey))
	log.Info("✅ Secret manager initialized")

	if configuration.IsProxyMode() {
		log.Info("🔄 Identity Provider Mode: PROXY (upstream provider)")
		if configuration.UpstreamProvider.ProviderURL != "" {
			log.Infof("🔗 Upstream OAuth2 Provider configured: %s", configuration.UpstreamProvider.ProviderURL)
		}
	} else {
		log.Info("🏠 Identity Provider Mode: LOCAL (local users)")
	}

	// Fetch and cache upstream OIDC discovery if upstream provider is configured
	if configuration.IsProxyMode() && configuration.UpstreamProvider.ProviderURL != "" && configuration.UpstreamProvider.ProviderURL != "https://example.com" {
		log.Infof("📡 Fetching upstream OIDC discovery from: %s", configuration.UpstreamProvider.ProviderURL+"/.well-known/openid-configuration")

		resp, err := http.Get(configuration.UpstreamProvider.ProviderURL + "/.well-known/openid-configuration")
		if err != nil {
			log.Fatalf("❌ Failed to fetch upstream OIDC discovery: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("❌ Upstream OIDC discovery returned status: %d", resp.StatusCode)
		}

		var upstreamMetadata map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&upstreamMetadata); err != nil {
			log.Fatalf("❌ Failed to decode upstream OIDC discovery: %v", err)
		}

		// Store the metadata in the config
		configuration.UpstreamProvider.Metadata = upstreamMetadata

		log.Debugf("✅ Fetched upstream OIDC discovery with %d metadata fields", len(upstreamMetadata))

		// Auto-register as client with upstream if no credentials provided and registration endpoint exists
		if configuration.UpstreamProvider.ClientID == "" && configuration.UpstreamProvider.ClientSecret == "" {
			if registrationEndpoint, ok := upstreamMetadata["registration_endpoint"].(string); ok && registrationEndpoint != "" {
				log.Info("🔧 No upstream client credentials provided, attempting auto-registration with upstream provider")

				// Get supported scopes, default to openid if not available
				upstreamScopes := []string{"openid"}
				if scopesSupported, ok := upstreamMetadata["scopes_supported"].([]interface{}); ok {
					upstreamScopes = make([]string, len(scopesSupported))
					for i, scope := range scopesSupported {
						if scopeStr, ok := scope.(string); ok {
							upstreamScopes[i] = scopeStr
						}
					}
				}

				registrationRequest := map[string]interface{}{
					"redirect_uris":              []string{configuration.Server.BaseURL + "/callback"},
					"client_name":                "OAuth2 Federation OP",
					"grant_types":                []string{"authorization_code"},
					"scope":                      strings.Join(upstreamScopes, " "),
					"response_types":             []string{"code"},
					"token_endpoint_auth_method": "client_secret_basic",
				}

				requestBody, err := json.Marshal(registrationRequest)
				if err != nil {
					log.Fatalf("❌ Failed to marshal client registration request: %v", err)
				}

				regReq, err := http.NewRequest("POST", registrationEndpoint, bytes.NewReader(requestBody))
				if err != nil {
					log.Fatalf("❌ Failed to create client registration request: %v", err)
				}
				regReq.Header.Set("Content-Type", "application/json")

				client := &http.Client{}
				regResp, err := client.Do(regReq)
				if err != nil {
					log.Fatalf("❌ Failed to register client with upstream provider: %v", err)
				}
				defer regResp.Body.Close()

				if regResp.StatusCode != http.StatusCreated && regResp.StatusCode != http.StatusOK {
					log.Fatalf("❌ Upstream client registration failed with status: %d", regResp.StatusCode)
				}

				var registrationResponse map[string]interface{}
				if err := json.NewDecoder(regResp.Body).Decode(&registrationResponse); err != nil {
					log.Fatalf("❌ Failed to decode client registration response: %v", err)
				}

				if clientID, ok := registrationResponse["client_id"].(string); ok && clientID != "" {
					configuration.UpstreamProvider.ClientID = clientID
					log.Printf("✅ Auto-registered client ID: %s", clientID)
				} else {
					log.Fatalf("❌ Client registration response missing client_id")
				}

				if clientSecret, ok := registrationResponse["client_secret"].(string); ok && clientSecret != "" {
					configuration.UpstreamProvider.ClientSecret = clientSecret
					log.Printf("✅ Auto-registered client secret")
				} else {
					log.Fatalf("❌ Client registration response missing client_secret")
				}

				log.Printf("✅ Successfully auto-registered as client with upstream provider")
			} else {
				log.Printf("⚠️  No upstream client credentials provided and no registration_endpoint found in upstream discovery")
			}
		} else {
			log.Printf("✅ Using provided upstream client credentials")
		}
	} else if configuration.UpstreamProvider.ProviderURL == "https://example.com" {
		log.Printf("⚠️  Upstream provider URL is example placeholder - skipping OIDC discovery fetch")
	}

	// Initialize metrics collector
	metricsCollector = metrics.NewMetricsCollector()
	log.Printf("✅ Metrics collector initialized")

	// Initialize stores based on configuration
	if configuration.Database.Type == "sqlite" {
		sqliteStore, err := store.NewSQLiteStore(configuration.Database.Path, log)
		if err != nil {
			log.Fatalf("❌ Failed to initialize SQLite store: %v", err)
		}
		dataStore = sqliteStore
		log.Printf("✅ SQLite store initialized at: %s", configuration.Database.Path)
	} else {
		// Default to memory store
		memoryStore := storage.NewMemoryStore()
		dataStore = store.NewMemoryStoreWrapper(memoryStore, log)
		log.Printf("✅ Memory store initialized")
	}

	// Initialize custom storage wrapper
	customStorage = store.NewCustomStorage(dataStore, log)
	log.Printf("✅ Custom storage wrapper initialized")

	// Initialize trust anchor handler with the customStorage
	trustAnchorHandler = handlers.NewTrustAnchorHandler(customStorage, log)

	// Now initialize clients with the hasher BEFORE initializing OAuth2 provider
	if err := initializeClients(); err != nil {
		log.Fatalf("❌ Failed to initialize clients: %v", err)
	}

	// In main() function, after initializing clients
	if configuration.IsLocalMode() {
		if err := initializeUsers(); err != nil {
			log.Fatalf("❌ Failed to initialize users: %v", err)
		}
	} else {
		log.Printf("🔄 Proxy mode: skipping local user initialization")
	}

	// Initialize attestation manager if attestation is enabled
	if configuration.Attestation != nil && configuration.Attestation.Enabled {
		// Load trust anchor certificates from config file
		trustAnchors, err := attestation.LoadTrustAnchorsFromConfig("config.yaml")
		if err != nil {
			log.Fatalf("❌ Failed to load trust anchors: %v", err)
		}
		log.Printf("✅ Loaded %d trust anchors", len(trustAnchors))

		// Create a wrapper function for dynamic config checking that matches the expected signature
		dynamicConfigChecker := func(clientID string) (*config.ClientAttestationConfig, bool) {
			return handlers.GetClientAttestationConfig(clientID, dataStore)
		}

		attestationManager = attestation.NewVerifierManager(configuration.Attestation, trustAnchors, log, dynamicConfigChecker, trustAnchorHandler.ResolvePath)
		if err := attestationManager.PreloadVerifiers(); err != nil {
			log.Fatalf("❌ Failed to preload attestation verifiers: %v", err)
		}
		log.Printf("✅ Attestation manager initialized with %d clients", len(configuration.Attestation.Clients))
	}

	// Initialize OAuth2 provider
	if err := initializeOAuth2Provider(); err != nil {
		log.Fatalf("❌ Failed to initialize OAuth2 provider: %v", err)
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
	log.Printf("🏥 Health check: %s/health", configuration.Server.BaseURL)
	log.Printf("📊 Metrics endpoint: %s/metrics", configuration.Server.BaseURL)
	log.Printf("📈 Status endpoint: %s/stats", configuration.Server.BaseURL)
	log.Printf("✅ Server is ready to accept requests")

	if err := http.ListenAndServe(fmt.Sprintf(":%d", configuration.Server.Port), nil); err != nil {
		log.Fatalf("❌ Server failed to start: %v", err)
	}
}

func initializeClients() error {
	// First, load any existing clients from the database
	if sqliteStore, ok := dataStore.(*store.SQLiteStore); ok {
		log.Printf("🔍 Loading existing clients from database...")
		clients, err := sqliteStore.GetAllClients(context.Background())
		if err != nil {
			log.Printf("⚠️ Failed to load clients from database: %v", err)
		} else {
			for _, client := range clients {
				customStorage.Clients[client.GetID()] = client
				log.Printf("✅ Loaded client from database: %s", client.GetID())
			}
			log.Printf("✅ Loaded %d clients from database", len(clients))
		}
	}

	// Register each client from configuration (this will overwrite any database clients with the same ID)
	for _, client := range configuration.Clients {
		hashedSecret, err := utils.HashSecret(client.Secret)
		if err != nil {
			return fmt.Errorf("failed to hash secret for client %s: %w", client.ID, err)
		}

		log.Println("Registering client:", client.ID)

		if len(client.Audience) == 0 {
			client.Audience = []string{client.ID}
		}

		if client.Public {
			// Add privileged client to audience for token introspection
			privilegedID := configuration.Security.PrivilegedClientID
			if privilegedID != "" {
				found := false
				for _, aud := range client.Audience {
					if aud == privilegedID {
						found = true
						break
					}
				}
				if !found {
					client.Audience = append(client.Audience, privilegedID)
				}
			}
		}

		// Store plain text secret for privileged clients
		if client.ID == configuration.Security.PrivilegedClientID {
			privilegedClientSecrets[client.ID] = client.Secret
			log.Printf("✅ Stored plain text secret for privileged client: %s", client.ID)
		}

		// Ensure client_credentials grant type is included when in proxy mode
		grantTypes := client.GrantTypes
		if configuration.IsProxyMode() {
			// Check if client_credentials is already in the grant types
			hasClientCredentials := false
			for _, gt := range grantTypes {
				if gt == "client_credentials" {
					hasClientCredentials = true
					break
				}
			}
			if !hasClientCredentials {
				grantTypes = append(grantTypes, "client_credentials")
				log.Printf("✅ Added client_credentials grant type to pre-configured client %s for proxy mode", client.ID)
			}
		}

		newClient := &fosite.DefaultClient{
			ID:            client.ID,
			Secret:        hashedSecret,
			RedirectURIs:  client.RedirectURIs,
			GrantTypes:    grantTypes,
			ResponseTypes: client.ResponseTypes,
			Scopes:        client.Scopes,
			Audience:      client.Audience,
			Public:        client.Public,
		}

		customStorage.Clients[client.ID] = newClient
		// Also persist to underlying storage for SQLite
		if err := customStorage.CreateClient(context.Background(), newClient); err != nil {
			log.Printf("⚠️ Failed to persist client %s to storage: %v", client.ID, err)
		}
	}

	log.Printf("✅ Stores initialized with %d clients", len(customStorage.Clients))

	// Update metrics with initial client count
	metricsCollector.UpdateRegisteredClients(float64(len(customStorage.Clients)))

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

			customStorage.Users[user.ID] = newUser

			log.Printf("✅ Registered user: %s (%s)", user.Username, user.ID)
		}
	}

	log.Printf("✅ User store initialized with %d users", len(customStorage.Users))

	// Update metrics with initial user count
	metricsCollector.UpdateRegisteredUsers(float64(len(customStorage.Users)))

	return nil
}

func initializeOAuth2Provider() error {
	log.Printf("🔍 Initializing OAuth2 provider...")
	log.Printf("🔍 Configuration: %v", configuration != nil)
	log.Printf("🔍 MemoryStore: %v", dataStore != nil)

	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}
	log.Printf("✅ RSA key generated")

	// Configure OAuth2 provider with minimal settings
	log.Printf("🔍 Configuration details:")
	log.Printf("🔍   Security.TokenExpirySeconds: %d", configuration.Security.TokenExpirySeconds)
	log.Printf("🔍   Security.JWTSecret length: %d", len(configuration.Security.JWTSecret))
	log.Printf("🔍   Server.BaseURL: %s", configuration.Server.BaseURL)
	config := &fosite.Config{
		AccessTokenLifespan:   time.Duration(configuration.Security.TokenExpirySeconds) * time.Second,
		RefreshTokenLifespan:  time.Duration(configuration.Security.RefreshTokenExpirySeconds) * time.Second,
		AuthorizeCodeLifespan: time.Duration(configuration.Security.AuthorizationCodeExpirySeconds) * time.Second,
		// Add some important configuration that might be missing
		ScopeStrategy:              fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:   fosite.DefaultAudienceMatchingStrategy,
		SendDebugMessagesToClients: true, // Enable debug messages for development
		// Set the HMAC secret from our configuration
		GlobalSecret: []byte(configuration.Security.JWTSecret),
		// Set the ID token issuer
		IDTokenIssuer: configuration.Server.BaseURL,
		// RFC 8693
		TokenExchangeEnabled: true,
		TokenExchangeTokenTypes: []string{
			"urn:ietf:params:oauth:token-type:access_token",
			"urn:ietf:params:oauth:token-type:refresh_token",
		},
	}
	log.Printf("✅ Fosite config created")

	// Set up custom client authentication strategy for attestation and proxy mode support
	if attestationManager != nil || configuration.IsProxyMode() {
		authStrategy := auth.NewClientAuthStrategy(attestationManager, customStorage, configuration)
		config.ClientAuthenticationStrategy = authStrategy
		log.Printf("✅ Custom client authentication strategy configured")
	}

	// Setup the RFC8693 handler...
	AccessTokenStrategy = compose.NewOAuth2HMACStrategy(config)
	RefreshTokenStrategy = compose.NewOAuth2HMACStrategy(config)
	log.Printf("✅ Token strategies created")

	// Custom storage should already be created in main()
	// Just ensure it's properly initialized
	if customStorage == nil {
		log.Fatalf("❌ Custom storage not initialized")
	}

	// Create a selective OAuth2 provider with only the features we need
	log.Printf("🔍 About to call compose.Compose with selective factories...")

	// Define key getter for JWT signing
	keyGetter := func(context.Context) (interface{}, error) {
		return privateKey, nil
	}

	oauth2Provider = compose.Compose(
		config,
		customStorage,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
			RFC8628CodeStrategy:        compose.NewDeviceStrategy(config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2ResourceOwnerPasswordCredentialsFactory,
		compose.RFC8628DeviceFactory,
		compose.RFC8628DeviceAuthorizationTokenFactory,
		compose.RFC8693TokenExchangeFactory,
	)
	log.Printf("✅ OAuth2 provider created")

	return nil
}

func initializeHandlers() {
	// Initialize OAuth2 handlers

	// Set version information in the handlers package
	handlers.SetVersionInfo(Version, GitCommit, BuildTime)

	registrationHandler = handlers.NewRegistrationHandler(customStorage, secretManager, trustAnchorHandler, attestationManager, configuration, log)
	healthHandler = handlers.NewHealthHandler(configuration, dataStore)
	oauth2DiscoveryHandler = handlers.NewOAuth2DiscoveryHandler(configuration, attestationManager)

	// Initialize OAuth2 flow handlers
	authorizeHandler = handlers.NewAuthorizeHandler(oauth2Provider, configuration, log, metricsCollector, customStorage, &UpstreamSessionMap)
	tokenHandler = handlers.NewTokenHandler(oauth2Provider, configuration, log, metricsCollector, attestationManager, customStorage, secretManager, &authCodeToStateMap, &deviceCodeToUpstreamMap, &accessTokenToIssuerStateMap)
	introspectionHandler = handlers.NewIntrospectionHandler(oauth2Provider, configuration, log, attestationManager, dataStore, secretManager, privilegedClientSecrets, &accessTokenToIssuerStateMap)
	authorizationIntrospectionHandler = handlers.NewAuthorizationIntrospectionHandler(oauth2Provider, configuration, log, dataStore, secretManager, privilegedClientSecrets, &accessTokenToIssuerStateMap)
	revokeHandler = handlers.NewRevokeHandler(oauth2Provider, log)
	userinfoHandler = handlers.NewUserInfoHandler(configuration, oauth2Provider, metricsCollector, log, dataStore)

	// Initialize discovery and utility handlers
	discoveryHandler = handlers.NewDiscoveryHandler(configuration)
	jwksHandler = handlers.NewJWKSHandler()
	statusHandler = handlers.NewStatusHandler(configuration)
	versionHandler = handlers.NewVersionHandler()
	claimsHandler = handlers.NewClaimsHandler(configuration, log)
	callbackHandler = handlers.NewCallbackHandler(configuration, log, &UpstreamSessionMap, &authCodeToStateMap, claimsHandler)

	// Initialize device flow handler
	deviceCodeHandler = handlers.NewDeviceCodeHandler(oauth2Provider, dataStore, secretManager, templates, configuration, log, &deviceCodeToUpstreamMap, &UpstreamSessionMap)

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
	// Metrics endpoint - register first
	http.Handle("/metrics", proxyAwareMiddleware(promhttp.Handler()))

	// OAuth2 callback endpoint - mode-aware (handles both proxy and local callbacks)
	http.Handle("/callback", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(callbackHandler.ServeHTTP))))

	// OAuth2 endpoints - use mode-aware handlers
	http.Handle("/authorize", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(authorizeHandler.ServeHTTP))))
	http.Handle("/token", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(tokenHandler.ServeHTTP))))
	http.Handle("/introspect", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(introspectionHandler.ServeHTTP))))
	http.Handle("/authorization-introspection", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(authorizationIntrospectionHandler.ServeHTTP))))
	http.Handle("/revoke", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(revokeHandler.ServeHTTP))))
	http.Handle("/userinfo", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(userinfoHandler.ServeHTTP))))

	// Device flow endpoints - use our custom device authorization but store in fosite-compatible format
	http.Handle("/device/authorize", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.HandleDeviceAuthorization))))
	http.Handle("/device", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.ShowVerificationPage))))
	http.Handle("/device/verify", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.HandleVerification))))
	http.Handle("/device/consent", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.HandleConsent))))

	// Registration endpoints
	http.Handle("/register", protectedMiddleware(log, configuration.Security.APIKey, configuration.Security.EnableRegistrationAPI)(metricsCollector.Middleware(http.HandlerFunc(registrationHandler.HandleRegistration))))
	http.Handle("/register/", protectedMiddleware(log, configuration.Security.APIKey, configuration.Security.EnableRegistrationAPI)(metricsCollector.Middleware(http.HandlerFunc(registrationHandler.HandleRegistration))))

	// Trust anchor management endpoints
	http.Handle("/trust-anchor/", protectedMiddleware(log, configuration.Security.APIKey, configuration.Security.EnableTrustAnchorAPI)(metricsCollector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the name from the path
		path := strings.TrimPrefix(r.URL.Path, "/trust-anchor/")
		if path == "" {
			// List all trust anchors
			trustAnchorHandler.HandleList(w, r)
			return
		}

		// Handle specific trust anchor by name
		switch r.Method {
		case "POST":
			trustAnchorHandler.HandleUpload(w, r, path)
		case "DELETE":
			trustAnchorHandler.HandleDelete(w, r, path)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))))

	// Discovery endpoints with CORS support
	http.Handle("/.well-known/oauth-authorization-server", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(oauth2DiscoveryHandler.ServeHTTP))))
	http.Handle("/.well-known/openid-configuration", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(discoveryHandler.ServeHTTP))))
	http.Handle("/.well-known/jwks.json", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(jwksHandler.ServeHTTP))))

	// Stats endpoint
	http.Handle("/stats", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statisticsHandler := handlers.StatisticsHandler{
			Storage: customStorage,
			Metrics: metricsCollector,
		}
		statisticsHandler.ServeHTTP(w, r)
	}))))

	// Health endpoint
	http.Handle("/health", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(healthHandler.ServeHTTP))))

	// Version endpoint
	http.Handle("/version", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(versionHandler.ServeHTTP))))

	// Claims display endpoints
	http.Handle("/claims", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(claimsHandler.ServeHTTP))))

	// Root status page
	http.Handle("/", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(statusHandler.ServeHTTP))))

	http.Handle("/status", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(statusHandler.ServeHTTP))))

	log.Printf("✅ Routes set up successfully")
}

// Combined middleware for all HTTP endpoints
func corsAndProxyMiddleware(handler http.Handler) http.Handler {
	return middleware.CORS(func(w http.ResponseWriter, r *http.Request) {
		proxyAwareMiddleware(handler).ServeHTTP(w, r)
	})
}

// Middleware for proxy awareness
func proxyAwareMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Store original values (with defaults for logging)
		originalHost := r.Host
		originalScheme := r.URL.Scheme
		if originalScheme == "" {
			originalScheme = "http" // Default assumption
		}

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
			r.Method, r.RequestURI,
			originalScheme, originalHost,
			r.URL.Scheme, r.Host)

		handler.ServeHTTP(w, r)
	})
}

// Combined middleware for protected HTTP endpoints (with API key auth)
func protectedMiddleware(log *logrus.Logger, apiKey string, enableAPI bool) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return middleware.APIKeyAuth(log, apiKey)(func(w http.ResponseWriter, r *http.Request) {
			if !enableAPI {
				log.Printf("❌ API endpoint disabled: %s", r.URL.Path)
				http.Error(w, "API endpoint disabled", http.StatusForbidden)
				return
			}
			corsAndProxyMiddleware(handler).ServeHTTP(w, r)
		})
	}
}
