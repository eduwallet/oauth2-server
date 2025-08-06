package handlers

import (
	"encoding/json"
	//	"fmt"
	"net/http"
	"net/url"

	"oauth2-server/internal/storage"
	"strings"
	"time"
)

// HandleUserInfo handles userinfo endpoint (OpenID Connect)
func (h *Handlers) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.writeError(w, "invalid_token", "Bearer token required", http.StatusUnauthorized)
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	if accessToken == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.writeError(w, "invalid_token", "Missing access token", http.StatusUnauthorized)
		return
	}

	tokenInfo, err := h.Storage.GetToken(accessToken)
	if err != nil {
		h.Logger.Debugf("UserInfo token validation failed: %v", err)
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.writeError(w, "invalid_token", "Invalid access token", http.StatusUnauthorized)
		return
	}

	if tokenInfo.ExpiresAt.Before(time.Now()) || !tokenInfo.Active {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.writeError(w, "invalid_token", "Token expired or inactive", http.StatusUnauthorized)
		return
	}

	if tokenInfo.TokenType != "access_token" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.writeError(w, "invalid_token", "Token is not an access token", http.StatusUnauthorized)
		return
	}

	hasOpenIDScope := false
	for _, scope := range tokenInfo.Scopes {
		if scope == "openid" {
			hasOpenIDScope = true
			break
		}
	}

	if !hasOpenIDScope {
		h.writeError(w, "insufficient_scope", "Token does not have openid scope", http.StatusForbidden)
		return
	}

	user := h.findUserByID(tokenInfo.UserID)
	if user == nil {
		h.writeError(w, "invalid_token", "User not found", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]interface{}{
		"sub": tokenInfo.UserID,
	}

	for _, scope := range tokenInfo.Scopes {
		switch scope {
		case "profile":
			userInfo["name"] = user.Name
		case "email":
			userInfo["email"] = user.Email
		}
	}

	h.Logger.Debugf("UserInfo request successful for user %s, client %s", tokenInfo.UserID, tokenInfo.ClientID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(userInfo)
}

// HandleLogin handles user login
func (h *Handlers) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"Error":       r.URL.Query().Get("error"),
			"RedirectURL": r.URL.Query().Get("redirect_url"),
		}

		if err := h.Templates.ExecuteTemplate(w, "login.html", data); err != nil {
			h.Logger.WithError(err).Error("Failed to render login template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		redirectURL := r.FormValue("redirect_url")

		if h.validateUser(username, password) {
			sessionID := generateRandomString(32)
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				Secure:   false, // Set to true in production with HTTPS
				MaxAge:   3600,
			})

			// Create SessionState struct instead of calling with separate parameters
			sessionState := &storage.SessionState{
				SessionID: sessionID,
				UserID:    username,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
				Active:    true,
				Extra:     make(map[string]interface{}),
			}

			// Store using the new interface signature
			if err := h.Storage.StoreSession(sessionState); err != nil {
				h.Logger.WithError(err).Error("Failed to store session")
			}

			if redirectURL == "" {
				redirectURL = "/"
			}

			h.Logger.Debugf("User login successful: username=%s", username)
			http.Redirect(w, r, redirectURL, http.StatusFound)
		} else {
			loginURL := "/login?error=invalid_credentials"
			if redirectURL != "" {
				loginURL += "&redirect_url=" + url.QueryEscape(redirectURL)
			}
			h.Logger.Debugf("User login failed: username=%s", username)
			http.Redirect(w, r, loginURL, http.StatusFound)
		}
	}
}
