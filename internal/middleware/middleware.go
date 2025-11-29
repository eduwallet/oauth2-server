package middleware

import (
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

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
