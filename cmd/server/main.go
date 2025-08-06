package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"oauth2-server/internal/config"
	"oauth2-server/internal/handlers"
	"oauth2-server/internal/storage"
)

// Global variables
var (
	log       = logrus.New()
	appConfig *config.Config
	templates *template.Template
	store     storage.Storage
	h         *handlers.Handlers
)

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

	// Initialize handlers
	h = handlers.NewHandlers(appConfig, store, templates, log)

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
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := store.CleanupExpired(); err != nil {
			log.WithError(err).Error("Failed to cleanup expired entries")
		}
	}
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

	return nil
}

func setupRoutes() {
	// OAuth2 endpoints
	http.HandleFunc("/oauth2/auth", proxyAwareMiddleware(h.HandleAuthorize))
	http.HandleFunc("/oauth2/token", proxyAwareMiddleware(h.HandleToken))
	http.HandleFunc("/oauth2/introspect", proxyAwareMiddleware(h.HandleIntrospect))
	http.HandleFunc("/oauth2/userinfo", proxyAwareMiddleware(h.HandleUserInfo))
	http.HandleFunc("/oauth2/revoke", proxyAwareMiddleware(h.HandleRevoke))

	// Dynamic Client Registration (RFC 7591)
	http.HandleFunc("/oauth2/register", proxyAwareMiddleware(h.HandleClientRegistration))

	// Device flow endpoints
	http.HandleFunc("/device/code", proxyAwareMiddleware(h.HandleDeviceCode))
	http.HandleFunc("/device/verify", proxyAwareMiddleware(h.HandleDeviceVerify))
	http.HandleFunc("/device/authorize", proxyAwareMiddleware(h.HandleDeviceAuthorize))
	http.HandleFunc("/device/poll", proxyAwareMiddleware(h.HandleDevicePoll))

	// Discovery endpoints
	http.HandleFunc("/.well-known/oauth-authorization-server", proxyAwareMiddleware(h.HandleOAuthDiscovery))
	http.HandleFunc("/.well-known/openid-configuration", proxyAwareMiddleware(h.HandleOpenIDDiscovery))
	http.HandleFunc("/.well-known/jwks.json", proxyAwareMiddleware(h.HandleJWKS))

	// Authentication endpoints
	http.HandleFunc("/login", proxyAwareMiddleware(h.HandleLogin))
	http.HandleFunc("/auth/consent", proxyAwareMiddleware(h.HandleConsent))

	// Static files and 
	http.HandleFunc("/health", proxyAwareMiddleware(healthHandler))
	http.HandleFunc("/", proxyAwareMiddleware(h.HandleRoot))

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

// Health handler
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"base_url":  appConfig.Server.BaseURL,
//		"clients":   len(clientStore.ListClients()),
	}

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
			originalBaseURL := appConfig.Server.BaseURL
			appConfig.Server.BaseURL = r.URL.Scheme + "://" + r.Host

			// Restore original BaseURL after request
			defer func() {
				appConfig.Server.BaseURL = originalBaseURL
			}()
		}

		// Log proxy information for debugging
		log.Printf("🔄 Proxy-aware request: %s %s (Original: %s://%s, Forwarded: %s://%s)",
			r.Method, r.RequestURI, originalScheme, originalHost, r.URL.Scheme, r.Host)

		handler(w, r)
	}
}
