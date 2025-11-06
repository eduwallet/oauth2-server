package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

// MetricsCollector holds all Prometheus metrics for the OAuth2 server
type MetricsCollector struct {
	// HTTP request metrics
	httpRequestsTotal    *prometheus.CounterVec
	httpRequestDuration  *prometheus.HistogramVec

	// OAuth2 operation metrics
	authRequestsTotal    *prometheus.CounterVec
	tokenRequestsTotal   *prometheus.CounterVec
	introspectRequestsTotal *prometheus.CounterVec
	userinfoRequestsTotal *prometheus.CounterVec

	// Token metrics
	tokensIssuedTotal    *prometheus.CounterVec
	activeTokens         prometheus.Gauge

	// Client and user metrics
	registeredClients    prometheus.Gauge
	registeredUsers      prometheus.Gauge

	// Error metrics
	errorsTotal          *prometheus.CounterVec

	// Business metrics
	authorizationCodesIssued prometheus.Counter
	accessTokensIssued       prometheus.Counter
	refreshTokensIssued      prometheus.Counter
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	mc := &MetricsCollector{
		// HTTP request metrics
		httpRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth2_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),

		httpRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "oauth2_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),

		// OAuth2 operation metrics
		authRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth2_auth_requests_total",
				Help: "Total number of authorization requests",
			},
			[]string{"client_id", "response_type", "status"},
		),

		tokenRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth2_token_requests_total",
				Help: "Total number of token requests",
			},
			[]string{"grant_type", "client_id", "status"},
		),

		introspectRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth2_introspect_requests_total",
				Help: "Total number of token introspection requests",
			},
			[]string{"client_id", "status"},
		),

		userinfoRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth2_userinfo_requests_total",
				Help: "Total number of userinfo requests",
			},
			[]string{"status", "error_reason"},
		),

		// Token metrics
		tokensIssuedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth2_tokens_issued_total",
				Help: "Total number of tokens issued",
			},
			[]string{"token_type", "grant_type"},
		),

		activeTokens: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "oauth2_active_tokens",
				Help: "Number of currently active tokens",
			},
		),

		// Client and user metrics
		registeredClients: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "oauth2_registered_clients",
				Help: "Number of registered OAuth2 clients",
			},
		),

		registeredUsers: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "oauth2_registered_users",
				Help: "Number of registered users",
			},
		),

		// Error metrics
		errorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oauth2_errors_total",
				Help: "Total number of errors",
			},
			[]string{"type", "endpoint"},
		),

		// Business metrics
		authorizationCodesIssued: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "oauth2_authorization_codes_issued_total",
				Help: "Total number of authorization codes issued",
			},
		),

		accessTokensIssued: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "oauth2_access_tokens_issued_total",
				Help: "Total number of access tokens issued",
			},
		),

		refreshTokensIssued: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "oauth2_refresh_tokens_issued_total",
				Help: "Total number of refresh tokens issued",
			},
		),
	}

	return mc
}

// RecordHTTPRequest records an HTTP request
func (mc *MetricsCollector) RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration) {
	mc.httpRequestsTotal.WithLabelValues(method, endpoint, strconv.Itoa(statusCode)).Inc()
	mc.httpRequestDuration.With(prometheus.Labels{
		"method":   method,
		"endpoint": endpoint,
	}).Observe(duration.Seconds())
}

// RecordAuthRequest records an authorization request
func (mc *MetricsCollector) RecordAuthRequest(clientID, responseType, status string) {
	mc.authRequestsTotal.WithLabelValues(clientID, responseType, status).Inc()
}

// RecordTokenRequest records a token request
func (mc *MetricsCollector) RecordTokenRequest(grantType, clientID, status string) {
	mc.tokenRequestsTotal.WithLabelValues(grantType, clientID, status).Inc()
}

// RecordIntrospectRequest records a token introspection request
func (mc *MetricsCollector) RecordIntrospectRequest(clientID, status string) {
	mc.introspectRequestsTotal.WithLabelValues(clientID, status).Inc()
}

// RecordUserinfoRequest records a userinfo request
func (mc *MetricsCollector) RecordUserinfoRequest(status, errorReason string) {
	if errorReason == "" {
		errorReason = "none"
	}
	mc.userinfoRequestsTotal.WithLabelValues(status, errorReason).Inc()
}

// RecordTokenIssued records when a token is issued
func (mc *MetricsCollector) RecordTokenIssued(tokenType, grantType string) {
	mc.tokensIssuedTotal.WithLabelValues(tokenType, grantType).Inc()

	switch tokenType {
	case "authorization_code":
		mc.authorizationCodesIssued.Inc()
	case "access_token":
		mc.accessTokensIssued.Inc()
	case "refresh_token":
		mc.refreshTokensIssued.Inc()
	}
}

// UpdateActiveTokens updates the gauge for active tokens
func (mc *MetricsCollector) UpdateActiveTokens(count float64) {
	mc.activeTokens.Set(count)
}

// UpdateRegisteredClients updates the gauge for registered clients
func (mc *MetricsCollector) UpdateRegisteredClients(count float64) {
	mc.registeredClients.Set(count)
}

// UpdateRegisteredUsers updates the gauge for registered users
func (mc *MetricsCollector) UpdateRegisteredUsers(count float64) {
	mc.registeredUsers.Set(count)
}

// RecordError records an error
func (mc *MetricsCollector) RecordError(errorType, endpoint string) {
	mc.errorsTotal.WithLabelValues(errorType, endpoint).Inc()
}

// Middleware creates an HTTP middleware for recording metrics
func (mc *MetricsCollector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Record metrics
		duration := time.Since(start)
		endpoint := getEndpointFromPath(r.URL.Path)

		mc.RecordHTTPRequest(r.Method, endpoint, rw.statusCode, duration)

		// Log slow requests
		if duration > time.Second {
			logrus.WithFields(logrus.Fields{
				"method":   r.Method,
				"path":     r.URL.Path,
				"duration": duration,
				"status":   rw.statusCode,
			}).Warn("Slow request detected")
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// getEndpointFromPath extracts a simplified endpoint name from the path
func getEndpointFromPath(path string) string {
	switch {
	case path == "/":
		return "root"
	case path == "/health":
		return "health"
	case path == "/metrics":
		return "metrics"
	case path == "/auth" || path == "/oauth/authorize":
		return "authorize"
	case path == "/oauth/token":
		return "token"
	case path == "/oauth/introspect":
		return "introspect"
	case path == "/userinfo":
		return "userinfo"
	case path == "/register":
		return "register"
	case path == "/.well-known/openid-configuration":
		return "discovery"
	case path == "/.well-known/jwks.json":
		return "jwks"
	case path == "/stats":
		return "stats"
	case path == "/device/authorize":
		return "device_authorize"
	default:
		return "other"
	}
}