package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/pkg/config"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

type UserInfoHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Configuration  *config.Config
}

// Enhanced userinfo handler with proper user lookup
func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	// Use fosite's introspection to validate the token
	ctx := r.Context()
	// We require the "openid" scope to allow access to this endpoint.
	_, requester, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &openid.DefaultSession{}, "openid")
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token is invalid or has expired."`)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// Get user info from token claims (the subject)
	subject := requester.GetSession().GetSubject()

	// Build user info response based on the user ID from the token
	var userInfo map[string]interface{}
	if user, found := h.Configuration.GetUserByID(subject); found {
		userInfo = map[string]interface{}{
			"sub":      user.ID,
			"name":     user.Name,
			"email":    user.Email,
			"username": user.Username,
		}
	} else {
		// This case should ideally not happen if tokens are issued correctly
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="User not found."`)
		http.Error(w, "User associated with token not found", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
