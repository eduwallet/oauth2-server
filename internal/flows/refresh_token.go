package flows

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"oauth2-server/internal/auth"
	"oauth2-server/internal/models"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// RefreshTokenFlow handles refresh token requests
type RefreshTokenFlow struct {
	clientStore *store.ClientStore
	tokenStore  *store.TokenStore
	config      *config.Config
}

// NewRefreshTokenFlow creates a new refresh token flow handler
func NewRefreshTokenFlow(clientStore *store.ClientStore, tokenStore *store.TokenStore, cfg *config.Config) *RefreshTokenFlow {
	return &RefreshTokenFlow{
		clientStore: clientStore,
		tokenStore:  tokenStore,
		config:      cfg,
	}
}

// Handle processes refresh token requests
func (f *RefreshTokenFlow) Handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔄 Processing refresh token request")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, "invalid_request", "Failed to parse request")
		return
	}

	grantType := r.FormValue("grant_type")
	refreshToken := r.FormValue("refresh_token")
	scope := r.FormValue("scope")

	if grantType != "refresh_token" {
		utils.WriteErrorResponse(w, "unsupported_grant_type", "Grant type must be refresh_token")
		return
	}

	if refreshToken == "" {
		utils.WriteErrorResponse(w, "invalid_request", "refresh_token is required")
		return
	}

	// Extract client credentials
	clientID, clientSecret, err := auth.ExtractClientCredentials(r)
	if err != nil {
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication required")
		return
	}

	// Authenticate client
	client, err := auth.AuthenticateClient(clientID, clientSecret, f.clientStore)
	if err != nil {
		log.Printf("❌ Client authentication failed for %s: %v", clientID, err)
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication failed")
		return
	}

	// Check if client is authorized for refresh_token grant
	if !auth.ClientHasGrantType(client, "refresh_token") {
		utils.WriteErrorResponse(w, "unauthorized_client", "Client not authorized for refresh_token grant")
		return
	}

	// Validate refresh token
	tokenInfo, valid := f.validateRefreshToken(refreshToken)
	if !valid {
		utils.WriteErrorResponse(w, "invalid_grant", "Invalid or expired refresh token")
		return
	}

	// Verify token belongs to the client
	if tokenInfo.ClientID != clientID {
		utils.WriteErrorResponse(w, "invalid_grant", "Refresh token does not belong to client")
		return
	}

	// Handle scope parameter - convert scopes to string for comparison
	originalScopeString := strings.Join(tokenInfo.Scopes, " ")
	var newScope string
	var newScopeSlice []string

	if scope != "" {
		// If scope is provided, it must be a subset of the original scope
		if !f.isScopeSubset(scope, originalScopeString) {
			utils.WriteErrorResponse(w, "invalid_scope", "Requested scope exceeds original scope")
			return
		}
		newScope = scope
		newScopeSlice = strings.Fields(scope)
	} else {
		newScope = originalScopeString
		newScopeSlice = tokenInfo.Scopes
	}

	// Generate new tokens using high-level functions (and store them)
	accessTokenExpiry := time.Hour
	refreshTokenExpiry := 24 * time.Hour

	newAccessToken, err := auth.GenerateAccessToken(f.tokenStore, tokenInfo.UserID, clientID, newScopeSlice, accessTokenExpiry)
	if err != nil {
		log.Printf("❌ Error generating access token: %v", err)
		utils.WriteServerError(w, "Failed to generate access token")
		return
	}

	newRefreshToken, err := auth.GenerateRefreshToken(f.tokenStore, tokenInfo.UserID, clientID, newScopeSlice, refreshTokenExpiry)
	if err != nil {
		log.Printf("❌ Error generating refresh token: %v", err)
		utils.WriteServerError(w, "Failed to generate refresh token")
		return
	}

	// Revoke old refresh token
	err = f.tokenStore.RevokeToken(refreshToken)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to revoke old refresh token: %v", err)
		// Continue anyway as new tokens are already issued
	}

	// Create response
	response := models.TokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: newRefreshToken,
		Scope:        newScope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Tokens refreshed for client: %s", clientID)
}

// validateRefreshToken validates a refresh token
func (f *RefreshTokenFlow) validateRefreshToken(token string) (*store.TokenInfo, bool) {
	if f.tokenStore == nil {
		return nil, false
	}

	tokenInfo, err := auth.ValidateToken(f.tokenStore, token)
	if err != nil {
		return nil, false
	}
	if tokenInfo.TokenType != "refresh_token" {
		return nil, false
	}

	return tokenInfo, true
}

// isScopeSubset checks if requestedScope is a subset of originalScope
func (f *RefreshTokenFlow) isScopeSubset(requestedScope, originalScope string) bool {
	requested := strings.Fields(requestedScope)
	original := strings.Fields(originalScope)

	for _, req := range requested {
		found := false
		for _, orig := range original {
			if req == orig {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
