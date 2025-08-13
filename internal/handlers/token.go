package handlers

import (
	"net/http"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/sirupsen/logrus"
)

// TokenHandler manages OAuth2 token requests using pure fosite implementation
type TokenHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Configuration  *config.Config
	Log            *logrus.Logger
}

// NewTokenHandler creates a new TokenHandler
func NewTokenHandler(
	provider fosite.OAuth2Provider,
	config *config.Config,
	logger *logrus.Logger,
) *TokenHandler {
	return &TokenHandler{
		OAuth2Provider: provider,
		Configuration:  config,
		Log:            logger,
	}
}

// ServeHTTP implements the http.Handler interface for the token endpoint
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.HandleTokenRequest(w, r)
}

// HandleTokenRequest processes OAuth2 token requests using pure fosite
func (h *TokenHandler) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ Failed to parse form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Debug logging
	grantType := r.FormValue("grant_type")
	h.Log.Printf("🔍 Token request - Grant Type: %s", grantType)

	// Let fosite handle ALL token requests natively, including device code flow
	// This removes all custom bridge logic and relies purely on fosite's implementation
	accessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, r, &openid.DefaultSession{})
	if err != nil {
		h.Log.Printf("❌ NewAccessRequest failed: %v", err)
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Let fosite create the access response
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Printf("❌ NewAccessResponse failed: %v", err)
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Let fosite write the response
	h.OAuth2Provider.WriteAccessResponse(ctx, w, accessRequest, accessResponse)

	h.Log.Printf("✅ Token request handled successfully by fosite")
}
