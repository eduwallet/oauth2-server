package handlers

import (
	"encoding/base64"
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

	// Log authentication headers with more detail
	authHeader := r.Header.Get("Authorization")
	h.Log.Printf("🔍 Authorization header present: %t", authHeader != "")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) > 0 {
			h.Log.Printf("🔍 Auth method: %s", parts[0])

			// DEBUG: Extract and log Basic Auth credentials (without exposing the secret)
			if parts[0] == "Basic" && len(parts) > 1 {
				// Decode the Basic Auth to get client ID (but not log the secret)
				if decoded, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
					credentials := string(decoded)
					if credParts := strings.Split(credentials, ":"); len(credParts) >= 2 {
						clientID := credParts[0]
						secretLength := len(credParts[1])
						h.Log.Printf("🔍 Basic Auth - Client ID: %s, Secret length: %d", clientID, secretLength)
					}
				}
			}
		}
	}

	// Ensure it's a POST request
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ Error parsing form: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Log form values (but hide sensitive data)
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	h.Log.Printf("🔍 Introspection details: token_present=%t, token_type_hint=%s", token != "", tokenTypeHint)
	h.Log.Printf("🔍 Client credentials in form: client_id_present=%t, client_secret_present=%t", clientID != "", clientSecret != "")

	// Create a session for introspection
	session := &fosite.DefaultSession{}

	// Create the introspection request
	ir, err := h.OAuth2Provider.NewIntrospectionRequest(ctx, r, session)
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
