package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"

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
	registrationHandler    *handlers.RegistrationHandler
	deviceCodeHandler      *handlers.DeviceCodeHandler
	introspectionHandler   *handlers.IntrospectionHandler
	discoveryHandler       *handlers.DiscoveryHandler
	homeHandler            *handlers.HomeHandler
	tokenHandler           *handlers.TokenHandler
	revokeHandler          *handlers.RevokeHandler
	jwksHandler            *handlers.JWKSHandler
	healthHandler          *handlers.HealthHandler
	oauth2DiscoveryHandler *handlers.OAuth2DiscoveryHandler
	authorizeHandler       *handlers.AuthorizeHandler

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
	log.Printf("🎫 Token endpoint: %s/oauth/token", configuration.Server.BaseURL)
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
			hashedSecret, err := utils.HashSecret(client.Secret)
			if err != nil {
				return fmt.Errorf("failed to hash secret for client %s: %w", client.ID, err)
			}

			log.Println("Registering client:", client.ID)

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

	// Configure OAuth2 provider with minimal settings
	config := &compose.Config{
		AccessTokenLifespan:   time.Duration(configuration.Security.TokenExpirySeconds) * time.Second,
		RefreshTokenLifespan:  time.Duration(configuration.Security.RefreshTokenExpirySeconds) * time.Second,
		AuthorizeCodeLifespan: time.Duration(configuration.Security.AuthorizationCodeExpirySeconds) * time.Second,
		// Add some important configuration that might be missing
		ScopeStrategy:              fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:   fosite.DefaultAudienceMatchingStrategy,
		SendDebugMessagesToClients: true, // Enable debug messages for development
	}

	// Create a simple OAuth2 provider without complex strategies
	oauth2Provider = compose.ComposeAllEnabled(
		config,
		memoryStore,
		[]byte(configuration.Security.JWTSecret),
		privateKey,
	)

	log.Printf("✅ OAuth2 provider initialized with fosite storage")
	return nil
}

func initializeHandlers() {
	// Initialize OAuth2 handlers

	registrationHandler = handlers.NewRegistrationHandler(memoryStore)
	introspectionHandler = handlers.NewIntrospectionHandler(oauth2Provider, log)
	deviceCodeHandler = handlers.NewDeviceCodeHandler(oauth2Provider, templates, configuration, log)
	discoveryHandler = handlers.NewDiscoveryHandler(configuration)
	homeHandler = handlers.NewHomeHandler(configuration)
	tokenHandler = handlers.NewTokenHandler(oauth2Provider, configuration, log)
	revokeHandler = handlers.NewRevokeHandler(oauth2Provider, log)
	jwksHandler = handlers.NewJWKSHandler()
	healthHandler = handlers.NewHealthHandler(configuration, memoryStore)
	oauth2DiscoveryHandler = handlers.NewOAuth2DiscoveryHandler(configuration)
	authorizeHandler = handlers.NewAuthorizeHandler(oauth2Provider, configuration, log)

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
	http.HandleFunc("/auth", proxyAwareMiddleware(authorizeHandler.ServeHTTP))  // Add /auth alias for authorization
	http.HandleFunc("/oauth/authorize", proxyAwareMiddleware(authorizeHandler.ServeHTTP))
	http.HandleFunc("/oauth/token", proxyAwareMiddleware(tokenHandler.ServeHTTP))
	http.HandleFunc("/oauth/introspect", proxyAwareMiddleware(introspectionHandler.ServeHTTP))
	http.HandleFunc("/oauth/revoke", proxyAwareMiddleware(revokeHandler.ServeHTTP))

	// Device flow endpoints - use our custom device authorization but store in fosite-compatible format
	http.HandleFunc("/device/authorize", proxyAwareMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// Use our custom device authorization handler
		// The key insight: we need to store device authorization in fosite's memory store format
		deviceCodeHandler.HandleDeviceAuthorization(w, r)
	}))
	http.HandleFunc("/device", proxyAwareMiddleware(deviceCodeHandler.ShowVerificationPage))
	http.HandleFunc("/device/verify", proxyAwareMiddleware(deviceCodeHandler.HandleVerification))
	// TODO: Add polling endpoint if needed
	// http.HandleFunc("/device/poll", proxyAwareMiddleware(deviceCodeHandler.HandleDevicePolling))

	// Registration endpoints
	http.HandleFunc("/register", proxyAwareMiddleware(registrationHandler.HandleRegistration))

	// Discovery endpoints
	http.HandleFunc("/.well-known/oauth-authorization-server", proxyAwareMiddleware(oauth2DiscoveryHandler.ServeHTTP))
	http.HandleFunc("/.well-known/openid-configuration", proxyAwareMiddleware(discoveryHandler.ServeHTTP))
	http.HandleFunc("/.well-known/jwks.json", proxyAwareMiddleware(jwksHandler.ServeHTTP))

	// Utility endpoints
	http.HandleFunc("/userinfo", proxyAwareMiddleware(func(w http.ResponseWriter, r *http.Request) {
		userinfoHandler := handlers.UserInfoHandler{
			Configuration:  configuration,
			OAuth2Provider: oauth2Provider,
		}
		userinfoHandler.ServeHTTP(w, r)
	}))

	// Stats endpoint
	http.HandleFunc("/stats", proxyAwareMiddleware(func(w http.ResponseWriter, r *http.Request) {
		statisticsHandler := handlers.StatisticsHandler{
			MemoryStore: memoryStore,
		}
		statisticsHandler.ServeHTTP(w, r)
	}))

	// Health endpoint
	http.HandleFunc("/health", proxyAwareMiddleware(healthHandler.ServeHTTP))
	http.HandleFunc("/", proxyAwareMiddleware(homeHandler.ServeHTTP))

	log.Printf("✅ Routes set up successfully")
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
