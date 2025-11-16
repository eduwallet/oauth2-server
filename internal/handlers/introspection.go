package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// responseCapture captures the response from Fosite to allow modification
type responseCapture struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{
		ResponseWriter: w,
		statusCode:     200,
		body:           &bytes.Buffer{},
	}
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
}

func (rc *responseCapture) Write(data []byte) (int, error) {
	return rc.body.Write(data)
}

// getSessionFromToken attempts to extract issuer_state from a JWT token
func (h *IntrospectionHandler) getIssuerStateFromToken(tokenValue string) interface{} {
	// JWT format: header.payload.signature
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		h.Log.Printf("❌ Error decoding JWT payload: %v", err)
		return nil
	}

	// Parse the JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		h.Log.Printf("❌ Error parsing JWT claims: %v", err)
		return nil
	}

	// Extract issuer_state from claims (Fosite includes Extra claims directly in JWT payload)
	if issuerState, exists := claims["issuer_state"]; exists {
		return issuerState
	}

	return nil
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

	// Parse form data first to check for client credentials
	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ Error parsing form: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// RFC 7662 allows client authentication via:
	// 1. Basic authentication in Authorization header
	// 2. client_id and client_secret in request body
	// 3. Other client authentication methods

	authHeader := r.Header.Get("Authorization")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	h.Log.Printf("🔍 Introspection auth check: auth_header_present=%t, client_id_present=%t, client_secret_present=%t",
		authHeader != "", clientID != "", clientSecret != "")

	// Check if we have some form of client authentication
	hasBasicAuth := authHeader != "" && strings.HasPrefix(authHeader, "Basic ")
	hasClientCreds := clientID != "" || clientSecret != ""

	if !hasBasicAuth && !hasClientCreds {
		h.Log.Printf("❌ No client authentication provided for introspection")
		http.Error(w, "Client authentication required for introspection", http.StatusUnauthorized)
		return
	}

	h.Log.Printf("🔍 Client authentication present for introspection")

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

		h.OAuth2Provider.WriteIntrospectionError(ctx, w, err)
		return
	}

	// Capture the response to add issuer_state
	capture := newResponseCapture(w)
	h.OAuth2Provider.WriteIntrospectionResponse(ctx, capture, ir)

	// Parse the JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(capture.body.Bytes(), &response); err != nil {
		h.Log.Printf("❌ Error parsing introspection response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Add issuer_state if the token is active
	if active, ok := response["active"].(bool); ok && active {
		// Parse the token to extract issuer_state from claims
		tokenValue := r.FormValue("token")
		if tokenValue != "" {
			if issuerState := h.getIssuerStateFromToken(tokenValue); issuerState != nil {
				response["issuer_state"] = issuerState
			}
		}
	}

	// Write the modified response
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(capture.statusCode)
	json.NewEncoder(w).Encode(response)
}
