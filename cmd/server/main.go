package main

import (
	"bytes"
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

	"github.com/joho/godotenv"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc8693"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"oauth2-server/internal/attestation"
	"oauth2-server/internal/handlers"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/middleware"
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
	memoryStore    *storage.MemoryStore

	// TokenStrategy
	AccessTokenStrategy  oauth2.AccessTokenStrategy
	RefreshTokenStrategy oauth2.RefreshTokenStrategy

	// Handlers
	registrationHandler    *handlers.RegistrationHandler
	deviceCodeHandler      *handlers.DeviceCodeHandler
	introspectionHandler   *handlers.IntrospectionHandler
	discoveryHandler       *handlers.DiscoveryHandler
	statusHandler          *handlers.StatusHandler
	tokenHandler           *handlers.TokenHandler
	revokeHandler          *handlers.RevokeHandler
	jwksHandler            *handlers.JWKSHandler
	healthHandler          *handlers.HealthHandler
	oauth2DiscoveryHandler *handlers.OAuth2DiscoveryHandler
	authorizeHandler       *handlers.AuthorizeHandler
	claimsHandler          *handlers.ClaimsHandler
	versionHandler         *handlers.VersionHandler
	userinfoHandler        *handlers.UserInfoHandler
	callbackHandler        *handlers.CallbackHandler
	trustAnchorHandler     *handlers.TrustAnchorHandler

	// Metrics collector
	metricsCollector *metrics.MetricsCollector

	// Attestation manager
	attestationManager *attestation.VerifierManager

	// Templates
	templates *template.Template
)

// Maps for persisting original authorization state through the OAuth2 flow in proxy mode
var authCodeToStateMap = make(map[string]string) // authorization_code -> original_state
var UpstreamSessionMap = make(map[string]handlers.UpstreamSessionData)

type TrustAnchorDispatcher struct {
	handler *handlers.TrustAnchorHandler
}

func (d *TrustAnchorDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: TrustAnchorDispatcher called for path: %s, method: %s", r.URL.Path, r.Method)
	if r.URL.Path == "/trust-anchor/" {
		// List all trust anchors
		d.handler.HandleList(w, r)
		return
	}

	// Extract name from path /trust-anchor/{name}
	name := strings.TrimPrefix(r.URL.Path, "/trust-anchor/")
	log.Printf("DEBUG: Extracted name: %s", name)
	if name == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "POST":
		d.handler.HandleUpload(w, r, name)
	case "DELETE":
		d.handler.HandleDelete(w, r, name)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

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

	var err error

	_ = godotenv.Load()
	if err != nil {
		log.Printf("No .env file loaded")
	}

	// Load configuration from YAML
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

	log.Printf("✅ Configuration loaded successfully")
	log.Printf("🔧 Log Level: %s, Format: %s, Audit: %t", logLevel, logFormat, enableAudit)

	if configuration.IsProxyMode() {
		log.Printf("🔄 Identity Provider Mode: PROXY (upstream provider)")
		if configuration.UpstreamProvider.ProviderURL != "" {
			log.Printf("🔗 Upstream OAuth2 Provider configured: %s", configuration.UpstreamProvider.ProviderURL)
		}
	} else {
		log.Printf("🏠 Identity Provider Mode: LOCAL (local users)")
	}

	// Fetch and cache upstream OIDC discovery if upstream provider is configured
	if configuration.IsProxyMode() && configuration.UpstreamProvider.ProviderURL != "" && configuration.UpstreamProvider.ProviderURL != "https://example.com" {
		log.Printf("📡 Fetching upstream OIDC discovery from: %s", configuration.UpstreamProvider.ProviderURL+"/.well-known/openid-configuration")

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

		log.Printf("✅ Fetched upstream OIDC discovery with %d metadata fields", len(upstreamMetadata))

		// Auto-register as client with upstream if no credentials provided and registration endpoint exists
		if configuration.UpstreamProvider.ClientID == "" && configuration.UpstreamProvider.ClientSecret == "" {
			if registrationEndpoint, ok := upstreamMetadata["registration_endpoint"].(string); ok && registrationEndpoint != "" {
				log.Printf("🔧 No upstream client credentials provided, attempting auto-registration with upstream provider")

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

	// Initialize attestation manager if attestation is enabled
	if configuration.Attestation != nil && configuration.Attestation.Enabled {
		// Load trust anchor certificates from config file
		trustAnchors, err := attestation.LoadTrustAnchorsFromConfig("config.yaml")
		if err != nil {
			log.Fatalf("❌ Failed to load trust anchors: %v", err)
		}
		log.Printf("✅ Loaded %d trust anchors", len(trustAnchors))

		attestationManager = attestation.NewVerifierManager(configuration.Attestation, trustAnchors, log)
		if err := attestationManager.PreloadVerifiers(); err != nil {
			log.Fatalf("❌ Failed to preload attestation verifiers: %v", err)
		}
		log.Printf("✅ Attestation manager initialized with %d clients", len(configuration.Attestation.Clients))
	}

	// Initialize stores
	memoryStore = storage.NewMemoryStore()

	// Initialize OAuth2 provider
	if err := initializeOAuth2Provider(); err != nil {
		log.Fatalf("❌ Failed to initialize OAuth2 provider: %v", err)
	}

	// Now initialize clients with the hasher
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
	// Load clients from config if any
	if len(configuration.Clients) > 0 {

		// Register each client in the memory store
		for _, client := range configuration.Clients {
			hashedSecret, err := utils.HashSecret(client.Secret)
			if err != nil {
				return fmt.Errorf("failed to hash secret for client %s: %w", client.ID, err)
			}

			log.Println("Registering client:", client.ID)

			if len(client.Audience) == 0 {
				client.Audience = []string{client.ID}
			}

			newClient := &fosite.DefaultClient{
				ID:            client.ID,
				Secret:        hashedSecret,
				RedirectURIs:  client.RedirectURIs,
				GrantTypes:    client.GrantTypes,
				ResponseTypes: client.ResponseTypes,
				Scopes:        client.Scopes,
				Audience:      client.Audience,
				Public:        client.Public,
			}

			memoryStore.Clients[client.ID] = newClient
		}
	}

	log.Printf("✅ Stores initialized with %d clients", len(memoryStore.Clients))

	// Update metrics with initial client count
	metricsCollector.UpdateRegisteredClients(float64(len(memoryStore.Clients)))

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

	// Update metrics with initial user count
	metricsCollector.UpdateRegisteredUsers(float64(len(memoryStore.Users)))

	return nil
}

func initializeOAuth2Provider() error {
	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Configure OAuth2 provider with minimal settings
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

	// Setup the RFC8693 handler...
	AccessTokenStrategy = compose.NewOAuth2HMACStrategy(config)
	RefreshTokenStrategy = compose.NewOAuth2HMACStrategy(config)

	// Create a simple OAuth2 provider without complex strategies
	oauth2Provider = compose.ComposeAllEnabled(
		config,
		memoryStore,
		privateKey,
	)

	// Initialize RFC8693 handler but don't append it to all token requests
	// The token exchange functionality should be handled by the default fosite provider
	// when TokenExchangeEnabled is true in the config
	_ = &rfc8693.Handler{
		Config:               config,
		AccessTokenStrategy:  AccessTokenStrategy,
		RefreshTokenStrategy: RefreshTokenStrategy,
		AccessTokenStorage:   memoryStore,
		RefreshTokenStorage:  memoryStore,
	}

	log.Printf("✅ OAuth2 provider initialized with fosite storage")
	return nil
}

func initializeHandlers() {
	// Initialize OAuth2 handlers

	// Set version information in the handlers package
	handlers.SetVersionInfo(Version, GitCommit, BuildTime)

	trustAnchorHandler = handlers.NewTrustAnchorHandler("/tmp/trust-anchors")
	registrationHandler = handlers.NewRegistrationHandler(memoryStore, trustAnchorHandler)
	healthHandler = handlers.NewHealthHandler(configuration, memoryStore)
	oauth2DiscoveryHandler = handlers.NewOAuth2DiscoveryHandler(configuration, attestationManager)

	// Initialize OAuth2 flow handlers
	authorizeHandler = handlers.NewAuthorizeHandler(oauth2Provider, configuration, log, metricsCollector, memoryStore, &UpstreamSessionMap)
	tokenHandler = handlers.NewTokenHandler(oauth2Provider, configuration, log, metricsCollector, attestationManager, memoryStore, &authCodeToStateMap)
	introspectionHandler = handlers.NewIntrospectionHandler(oauth2Provider, log)
	revokeHandler = handlers.NewRevokeHandler(oauth2Provider, log)
	userinfoHandler = handlers.NewUserInfoHandler(configuration, oauth2Provider, metricsCollector)

	// Initialize discovery and utility handlers
	discoveryHandler = handlers.NewDiscoveryHandler(configuration)
	jwksHandler = handlers.NewJWKSHandler()
	statusHandler = handlers.NewStatusHandler(configuration)
	versionHandler = handlers.NewVersionHandler()
	claimsHandler = handlers.NewClaimsHandler(configuration, log)
	callbackHandler = handlers.NewCallbackHandler(configuration, log, &UpstreamSessionMap, &authCodeToStateMap, claimsHandler)

	// Initialize device flow handler
	deviceCodeHandler = handlers.NewDeviceCodeHandler(oauth2Provider, memoryStore, templates, configuration, log)

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
	http.Handle("/revoke", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(revokeHandler.ServeHTTP))))
	http.Handle("/userinfo", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(userinfoHandler.ServeHTTP))))

	// Device flow endpoints - use our custom device authorization but store in fosite-compatible format
	http.Handle("/device/authorize", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.HandleDeviceAuthorization))))
	http.Handle("/device", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.ShowVerificationPage))))
	http.Handle("/device/verify", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.HandleVerification))))
	http.Handle("/device/consent", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(deviceCodeHandler.HandleConsent))))

	// Registration endpoints
	http.Handle("/register", corsAndProxyMiddleware(metricsCollector.Middleware(http.HandlerFunc(registrationHandler.HandleRegistration))))

	// Trust anchor management endpoints
	http.Handle("/trust-anchor/", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			MemoryStore: memoryStore,
			Metrics:     metricsCollector,
		}
		statisticsHandler.ServeHTTP(w, r)
	}))))

	// Health endpoint
	http.Handle("/health", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(healthHandler.ServeHTTP))))

	// Version endpoint
	http.Handle("/version", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(versionHandler.ServeHTTP))))

	// Claims display endpoints
	http.Handle("/claims", proxyAwareMiddleware(metricsCollector.Middleware(http.HandlerFunc(claimsHandler.ServeHTTP))))

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

		handler.ServeHTTP(w, r)
	})
}
