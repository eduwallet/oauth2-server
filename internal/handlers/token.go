package handlers

import (
	"net/http"
	"oauth2-server/internal/utils"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// TokenHandler manages OAuth2 token requests
type TokenHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Log            *logrus.Logger
}

// NewTokenHandler creates a new token handler
func NewTokenHandler(oauth2Provider fosite.OAuth2Provider, log *logrus.Logger) *TokenHandler {
	return &TokenHandler{
		OAuth2Provider: oauth2Provider,
		Log:            log,
	}
}

// ServeHTTP handles token requests and routes to appropriate flow
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		utils.WriteInvalidRequestError(w, "Failed to parse request")
		return
	}

	grantType := r.FormValue("grant_type")
	h.Log.Printf("🔄 Processing token request with grant_type: %s", grantType)

	switch grantType {
	default:
		// Let fosite handle ALL standard grant types INCLUDING token exchange
		h.handleStandardTokenRequest(w, r)
	}
}

func (h *TokenHandler) handleStandardTokenRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Let fosite handle ALL token requests including token exchange
	accessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
	if err != nil {
		h.Log.Printf("❌ Error creating access request: %v", err)
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Enhance session with user info for authorization code flow
	session := accessRequest.GetSession()
	if defaultSession, ok := session.(*fosite.DefaultSession); ok {
		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			defaultSession.Subject = h.extractUserFromAuthCode(accessRequest)
		case "client_credentials":
			defaultSession.Subject = accessRequest.GetClient().GetID()
			// Remove token exchange handling - fosite does this automatically
		}
	}

	response, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Printf("❌ Error creating access response: %v", err)
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	h.OAuth2Provider.WriteAccessResponse(ctx, w, accessRequest, response)
}

// Helper function to extract user from authorization code
func (h *TokenHandler) extractUserFromAuthCode(req fosite.AccessRequester) string {
	// This would need to be implemented based on your session storage
	// For now, return a default user
	return "user123"
}
