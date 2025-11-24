package middleware

import (
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// CORS middleware
func CORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Allow specific origins for demo app
		allowedOrigins := []string{
			"https://demo-app.oauth2-server.orb.local",
			"http://localhost:8001",
			"https://localhost:8001",
		}

		// Check if origin is allowed
		allowOrigin := ""
		for _, allowed := range allowedOrigins {
			if allowed == origin {
				allowOrigin = allowed
				break
			}
		}

		// If no specific match, allow all for development
		if allowOrigin == "" {
			allowOrigin = "*"
		}

		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		if allowOrigin != "*" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// APIKeyAuth middleware for API key authentication
func APIKeyAuth(log *logrus.Logger, apiKey string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Allow OPTIONS requests through for CORS preflight
			if r.Method == "OPTIONS" {
				log.Printf("🔄 Allowing OPTIONS request through for CORS preflight")
				next.ServeHTTP(w, r)
				return
			}

			if apiKey == "" {
				log.Printf("⚠️  API key authentication disabled (no API key configured: '%s')", apiKey)
				next.ServeHTTP(w, r)
				return
			}

			// Check for API key in header
			authHeader := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if authHeader == "" {
				log.Printf("❌ API key authentication failed: missing X-API-Key header")
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}

			if authHeader != strings.TrimSpace(apiKey) {
				log.Printf("❌ API key authentication failed: invalid API key")
				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}

			log.Printf("✅ API key authentication successful")
			next.ServeHTTP(w, r)
		}
	}
}
