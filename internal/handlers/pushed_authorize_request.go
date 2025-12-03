package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// PARRequest represents a pushed authorization request
type PARRequest struct {
	RequestURI string            `json:"request_uri"`
	ClientID   string            `json:"client_id"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Parameters map[string]string `json:"parameters"`
}

// PushedAuthorizeRequestHandler manages Pushed Authorization Requests
type PushedAuthorizeRequestHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Configuration  *config.Config
	Log            *logrus.Logger
	Storage        store.Storage
}

// NewPushedAuthorizeRequestHandler creates a new PAR handler
func NewPushedAuthorizeRequestHandler(oauth2Provider fosite.OAuth2Provider, configuration *config.Config, log *logrus.Logger, storage store.Storage) *PushedAuthorizeRequestHandler {
	return &PushedAuthorizeRequestHandler{
		OAuth2Provider: oauth2Provider,
		Configuration:  configuration,
		Log:            log,
		Storage:        storage,
	}
}

// ServeHTTP handles PAR requests
func (h *PushedAuthorizeRequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("🚀 [PUSHED-AUTHORIZE-REQUEST-HANDLER] Pushed Authorization Request received: %s %s", r.Method, r.URL.String())

	if r.Method != http.MethodPost {
		h.Log.Errorf("❌ [PUSHED-AUTHORIZE-REQUEST-HANDLER] Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.Log.Errorf("❌ [PUSHED-AUTHORIZE-REQUEST-HANDLER] Failed to parse form: %v", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Extract client_id
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		h.Log.Errorf("❌ [PUSHED-AUTHORIZE-REQUEST-HANDLER] Missing client_id")
		http.Error(w, "Missing client_id", http.StatusBadRequest)
		return
	}

	// Validate client exists
	if _, err := h.Storage.GetClient(r.Context(), clientID); err != nil {
		h.Log.Errorf("❌ [PUSHED-AUTHORIZE-REQUEST-HANDLER] Client validation failed: %v", err)
		http.Error(w, "Unknown client", http.StatusBadRequest)
		return
	}

	// Generate request URI
	requestURI, err := h.generateRequestURI()
	if err != nil {
		h.Log.Errorf("❌ [PUSHED-AUTHORIZE-REQUEST-HANDLER] Failed to generate request URI: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store PAR request parameters
	parameters := make(map[string]string)
	for key, values := range r.Form {
		if len(values) > 0 {
			parameters[key] = values[0]
		}
	}

	parRequest := &store.PARRequest{
		RequestURI: requestURI,
		ClientID:   clientID,
		ExpiresAt:  time.Now().Add(10 * time.Minute), // PAR requests expire in 10 minutes per RFC
		Parameters: parameters,
	}

	// Store in storage
	if err := h.Storage.StorePARRequest(r.Context(), parRequest); err != nil {
		h.Log.Errorf("❌ [PUSHED-AUTHORIZE-REQUEST-HANDLER] Failed to store PAR request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.Log.Printf("✅ [PUSHED-AUTHORIZE-REQUEST-HANDLER] PAR request stored with URI: %s", requestURI)

	// Return response
	response := map[string]interface{}{
		"request_uri": requestURI,
		"expires_in":  600, // 10 minutes in seconds
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	json.NewEncoder(w).Encode(response)
}

// generateRequestURI generates a unique request URI for PAR
func (h *PushedAuthorizeRequestHandler) generateRequestURI() (string, error) {
	// Generate random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Base64url encode
	encoded := base64.RawURLEncoding.EncodeToString(bytes)

	// Create request URI
	requestURI := "urn:ietf:params:oauth:request_uri:" + encoded

	return requestURI, nil
}

// GetPARRequest retrieves a stored PAR request by URI
func (h *PushedAuthorizeRequestHandler) GetPARRequest(ctx context.Context, requestURI string) (*store.PARRequest, error) {
	return h.Storage.GetPARRequest(ctx, requestURI)
}

// DeletePARRequest removes a stored PAR request
func (h *PushedAuthorizeRequestHandler) DeletePARRequest(ctx context.Context, requestURI string) error {
	return h.Storage.DeletePARRequest(ctx, requestURI)
}
