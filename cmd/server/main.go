package main

import (
	"context"
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
	http.HandleFunc("/oauth2/auth", h.HandleAuthorize)
	http.HandleFunc("/oauth2/token", h.HandleToken)
	http.HandleFunc("/oauth2/introspect", h.HandleIntrospect)
	http.HandleFunc("/oauth2/userinfo", h.HandleUserInfo)
	http.HandleFunc("/oauth2/revoke", h.HandleRevoke)

	// Dynamic Client Registration (RFC 7591)
	http.HandleFunc("/oauth2/register", h.HandleClientRegistration)

	// Device flow endpoints
	http.HandleFunc("/device/code", h.HandleDeviceCode)
	http.HandleFunc("/device/verify", h.HandleDeviceVerify)
	http.HandleFunc("/device/authorize", h.HandleDeviceAuthorize)
	http.HandleFunc("/device/poll", h.HandleDevicePoll)

	// Discovery endpoints
	http.HandleFunc("/.well-known/oauth-authorization-server", h.HandleOAuthDiscovery)
	http.HandleFunc("/.well-known/openid-configuration", h.HandleOpenIDDiscovery)
	http.HandleFunc("/.well-known/jwks.json", h.HandleJWKS)

	// Authentication endpoints
	http.HandleFunc("/login", h.HandleLogin)
	http.HandleFunc("/auth/consent", h.HandleConsent)

	// Static files and root
	http.HandleFunc("/", h.HandleRoot)

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
