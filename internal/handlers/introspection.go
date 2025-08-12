package handlers

import (
	"net/http"
	"strings"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// IntrospectionHandler manages token introspection requests
type IntrospectionHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Log            *logrus.Logger
}

// NewIntrospectionHandler creates a new introspection handler
func NewIntrospectionHandler(oauth2Provider fosite.OAuth2Provider, log *logrus.Logger) *IntrospectionHandler {
	return &IntrospectionHandler{
		OAuth2Provider: oauth2Provider,
		Log:            log,
	}
}

// ServeHTTP handles token introspection requests (RFC 7662)
func (h *IntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Log the incoming request for debugging
	h.Log.Printf("🔍 Introspection request: Method=%s, Content-Type=%s", r.Method, r.Header.Get("Content-Type"))

	// Ensure it's a POST request
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Log authentication headers with more detail
	authHeader := r.Header.Get("Authorization")
	h.Log.Printf("🔍 Authorization header present: %t", authHeader != "")

	if authHeader == "" {
		h.Log.Printf("❌ Missing Authorization header for introspection")
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		h.Log.Printf("❌ Invalid Authorization header format")
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	authMethod := parts[0]

	h.Log.Printf("🔍 Auth method: %s", authMethod)

	// According to RFC 7662 and fosite documentation, introspection requires Bearer token
	if authMethod != "Bearer" {
		h.Log.Printf("❌ Invalid authentication method for introspection. Expected Bearer, got: %s", authMethod)
		http.Error(w, "Bearer token required for introspection", http.StatusUnauthorized)
		return
	}

	h.Log.Printf("🔍 Bearer token present for introspection authorization")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ Error parsing form: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Log form values (but hide sensitive data)
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	//	clientID := r.FormValue("client_id")
	//	clientSecret := r.FormValue("client_secret")

	h.Log.Printf("🔍 Introspection details: token_present=%t, token_type_hint=%s", token != "", tokenTypeHint)

	// Create the introspection request
	ir, err := h.OAuth2Provider.NewIntrospectionRequest(ctx, r, newSession())
	if err != nil {
		h.Log.Printf("❌ Error creating introspection request: %v", err)

		// Provide more specific error information
		switch err.Error() {
		case "request_unauthorized":
			h.Log.Printf("❌ Client authentication failed for introspection")
			h.Log.Printf("🔍 This usually means: 1) Missing/invalid client credentials, 2) Client not authorized for introspection, 3) Wrong auth method")
		case "invalid_request":
			h.Log.Printf("❌ Invalid introspection request format")
		default:
			h.Log.Printf("❌ Introspection error details: %v", err)
		}

		h.OAuth2Provider.WriteIntrospectionError(w, err)
		return
	}

	// Write the successful introspection response
	h.OAuth2Provider.WriteIntrospectionResponse(w, ir)
}
