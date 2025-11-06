package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"oauth2-server/internal/metrics"
	"oauth2-server/pkg/config"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

type UserInfoHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Configuration  *config.Config
	Metrics        *metrics.MetricsCollector
}

// Enhanced userinfo handler with proper user lookup
func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "missing_auth_header")
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "invalid_auth_header")
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	// Use fosite's introspection to validate the token
	ctx := r.Context()
	_, requester, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &openid.DefaultSession{})
	if err != nil {
		log.Printf("❌ UserInfo: Token introspection failed: %v", err)
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "invalid_token")
		}

		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token is invalid or has expired."`)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	log.Printf("✅ UserInfo: Token validated successfully")

	// Get user info from token claims (the subject)
	session := requester.GetSession()
	if session == nil {
		log.Printf("❌ UserInfo: No session found in token")
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "no_session")
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="No session found in token."`)
		http.Error(w, "Invalid token session", http.StatusUnauthorized)
		return
	}

	subject := session.GetSubject()
	username := session.GetUsername()

	log.Printf("🔍 UserInfo: Token subject='%s', username='%s'", subject, username)

	// Check if this is a client credentials flow (no user context)
	if subject == "" && username == "" {
		log.Printf("❌ UserInfo: Client credentials token - no user context available")
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "no_user_context")
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="UserInfo endpoint requires user-authenticated tokens."`)
		http.Error(w, "UserInfo requires user authentication", http.StatusUnauthorized)
		return
	}

	// Try to find user by subject first, then by username
	var userInfo map[string]interface{}
	var user *config.UserConfig
	var found bool

	if subject != "" {
		user, found = h.Configuration.GetUserByID(subject)
		if !found {
			user, found = h.Configuration.GetUserByUsername(subject)
		}
	}

	if !found && username != "" {
		user, found = h.Configuration.GetUserByUsername(username)
		if !found {
			user, found = h.Configuration.GetUserByID(username)
		}
	}

	if found {
		log.Printf("✅ UserInfo: Found user: %s (%s)", user.Username, user.Name)
		userInfo = map[string]interface{}{
			"sub":      user.ID,
			"name":     user.Name,
			"email":    user.Email,
			"username": user.Username,
		}
	} else {
		log.Printf("❌ UserInfo: User not found for subject='%s', username='%s'", subject, username)
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "user_not_found")
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="User not found."`)
		http.Error(w, "User associated with token not found", http.StatusUnauthorized)
		return
	}

	if h.Metrics != nil {
		h.Metrics.RecordUserinfoRequest("success", "")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
