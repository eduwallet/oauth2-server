package middleware

import (
	"log"
	"net/http"
	"time"
)

// Logger middleware for request logging
func Logger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		log.Printf("📝 %s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, duration)
	}
}

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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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

// ProxyAware middleware for handling proxy headers
func ProxyAware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Handle X-Forwarded headers for proxy setups
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			r.URL.Scheme = proto
		}
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			r.Host = host
		}
		next.ServeHTTP(w, r)
	}
}

// RateLimiting middleware (basic implementation)
func RateLimit(requestsPerMinute int) func(http.HandlerFunc) http.HandlerFunc {
	clients := make(map[string][]time.Time)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			clientIP := r.RemoteAddr
			now := time.Now()

			// Clean old requests
			if requests, exists := clients[clientIP]; exists {
				var validRequests []time.Time
				for _, reqTime := range requests {
					if now.Sub(reqTime) < time.Minute {
						validRequests = append(validRequests, reqTime)
					}
				}
				clients[clientIP] = validRequests
			}

			// Check rate limit
			if len(clients[clientIP]) >= requestsPerMinute {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Add current request
			clients[clientIP] = append(clients[clientIP], now)

			next.ServeHTTP(w, r)
		}
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
