package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"oauth2-server/internal/auth"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
)

// TokenHandlers handles token-related endpoints
type TokenHandlers struct {
	clientStore *store.ClientStore
	tokenStore  *store.TokenStore
	config      *config.Config
}

// NewTokenHandlers creates a new token handlers instance
func NewTokenHandlers(clientStore *store.ClientStore, tokenStore *store.TokenStore, cfg *config.Config) *TokenHandlers {
	return &TokenHandlers{
		clientStore: clientStore,
		tokenStore:  tokenStore,
		config:      cfg,
	}
}

// HandleTokenRevocation handles token revocation requests (RFC 7009)
func (h *TokenHandlers) HandleTokenRevocation(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔄 Processing token revocation request")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, "invalid_request", "Failed to parse request")
		return
	}

	token := r.FormValue("token")

	if token == "" {
		utils.WriteErrorResponse(w, "invalid_request", "token is required")
		return
	}

	// Extract client credentials
	clientID, clientSecret, err := auth.ExtractClientCredentials(r)
	if err != nil {
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication required")
		return
	}

	// Authenticate client
	_, err = auth.AuthenticateClient(clientID, clientSecret, h.clientStore)
	if err != nil {
		log.Printf("❌ Client authentication failed for %s: %v", clientID, err)
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication failed")
		return
	}

	// Validate that the token belongs to the client
	tokenInfo, err := auth.ValidateToken(h.tokenStore, token)
	if err != nil {
		// Token not found or invalid - per RFC 7009, we should return success anyway
		log.Printf("⚠️ Token not found or invalid: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Verify token belongs to the client
	if tokenInfo.ClientID != clientID {
		log.Printf("⚠️ Token does not belong to client %s", clientID)
		w.WriteHeader(http.StatusOK) // Per RFC 7009, return success even if token doesn't belong to client
		return
	}

	// Revoke the token
	err = h.tokenStore.RevokeToken(token)
	if err != nil {
		log.Printf("❌ Failed to revoke token: %v", err)
		utils.WriteServerError(w, "Failed to revoke token")
		return
	}

	log.Printf("✅ Token revoked for client: %s", clientID)
	w.WriteHeader(http.StatusOK)
}

// HandleTokenIntrospection handles token introspection requests (RFC 7662)
func (h *TokenHandlers) HandleTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔍 Processing token introspection request")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, "invalid_request", "Failed to parse request")
		return
	}

	token := r.FormValue("token")

	if token == "" {
		utils.WriteErrorResponse(w, "invalid_request", "token is required")
		return
	}

	// Extract client credentials
	clientID, clientSecret, err := auth.ExtractClientCredentials(r)
	if err != nil {
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication required")
		return
	}

	// Authenticate client
	_, err = auth.AuthenticateClient(clientID, clientSecret, h.clientStore)
	if err != nil {
		log.Printf("❌ Client authentication failed for %s: %v", clientID, err)
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication failed")
		return
	}

	// Validate token and get info using high-level API
	tokenInfo, err := auth.ValidateToken(h.tokenStore, token)
	if err != nil {
		response := map[string]interface{}{
			"active": false,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create introspection response
	response := map[string]interface{}{
		"active":     tokenInfo.Active,
		"token_type": tokenInfo.TokenType,
		"client_id":  tokenInfo.ClientID,
		"username":   tokenInfo.UserID,
		"exp":        tokenInfo.ExpiresAt.Unix(),
		"iat":        tokenInfo.IssuedAt.Unix(),
		"iss":        tokenInfo.Issuer,
		"aud":        tokenInfo.Audience,
	}

	// Fix: Use tokenInfo.Scopes (slice) and join them
	if len(tokenInfo.Scopes) > 0 {
		response["scope"] = strings.Join(tokenInfo.Scopes, " ")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Token introspection completed for client: %s", clientID)
}

// handleTokenExchange processes token exchange requests (RFC 8693)
func (h *TokenHandlers) HandleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		utils.WriteMethodNotAllowedError(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.WriteInvalidRequestError(w, "Failed to parse request")
		return
	}

	// Extract and validate client credentials
	clientID, clientSecret, err := auth.ExtractClientCredentials(r)
	if err != nil {
		utils.WriteInvalidClientError(w, "Client authentication required")
		return
	}

	// Authenticate client
	if err := h.clientStore.ValidateClientCredentials(clientID, clientSecret); err != nil {
		utils.WriteInvalidClientError(w, "Invalid client credentials")
		return
	}

	// Validate required parameters
	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")
	audience := r.FormValue("audience")

	if subjectToken == "" {
		utils.WriteInvalidRequestError(w, "subject_token is required")
		return
	}

	if subjectTokenType == "" {
		utils.WriteInvalidRequestError(w, "subject_token_type is required")
		return
	}

	// Validate subject token type
	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" &&
		subjectTokenType != "urn:ietf:params:oauth:token-type:refresh_token" &&
		subjectTokenType != "urn:ietf:params:oauth:token-type:id_token" {
		utils.WriteUnsupportedGrantTypeError(w, "Unsupported subject_token_type")
		return
	}

	// Validate the subject token
	tokenInfo, err := auth.ValidateToken(h.tokenStore, subjectToken)
	if err != nil {
		utils.WriteInvalidGrantError(w, "Invalid or expired subject_token")
		return
	}

	// Optional: Validate audience if provided
	if audience != "" && !h.validateAudience(clientID, audience) {
		utils.WriteInvalidRequestError(w, "Invalid audience")
		return
	}

	// Determine the scope for the new token
	requestedScope := r.FormValue("scope")
	originalScope := strings.Join(tokenInfo.Scopes, " ")
	scope := h.determineTokenExchangeScope(originalScope, requestedScope)
	scopeSlice := strings.Fields(scope)

	// Generate and store new access token
	newAccessToken, err := auth.GenerateAccessToken(h.tokenStore, tokenInfo.UserID, clientID, scopeSlice, time.Hour)
	if err != nil {
		utils.WriteServerError(w, "Failed to generate access token")
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"access_token":      newAccessToken,
		"token_type":        "Bearer",
		"expires_in":        3600,
		"scope":             scope,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
	}

	// Optional: Include refresh token if appropriate
	if strings.Contains(scope, "offline_access") {
		refreshToken, err := auth.GenerateRefreshToken(h.tokenStore, tokenInfo.UserID, clientID, scopeSlice, 24*time.Hour)
		if err == nil {
			response["refresh_token"] = refreshToken
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)

	log.Printf("✅ Token exchange completed for client: %s, user: %s", clientID, tokenInfo.UserID)
}

// handleClientCredentials processes client credentials requests (RFC 6749 Section 4.4)
func (h *TokenHandlers) HandleClientCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		utils.WriteMethodNotAllowedError(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.WriteInvalidRequestError(w, "Failed to parse request")
		return
	}

	// Extract and validate client credentials
	clientID, clientSecret, err := auth.ExtractClientCredentials(r)
	if err != nil {
		utils.WriteInvalidClientError(w, "Client authentication required")
		return
	}

	// Authenticate client
	client, err := h.clientStore.GetClient(r.Context(), clientID)
	if err != nil {
		utils.WriteInvalidClientError(w, "Invalid client")
		return
	}

	if err := h.clientStore.ValidateClientCredentials(clientID, clientSecret); err != nil {
		utils.WriteInvalidClientError(w, "Invalid client credentials")
		return
	}

	// Check if client is authorized for client_credentials grant
	if !h.clientSupportsGrantType(client, "client_credentials") {
		utils.WriteInvalidRequestError(w, "Client not authorized for client_credentials grant")
		return
	}

	// Validate requested scope
	requestedScope := r.FormValue("scope")
	if requestedScope == "" {
		requestedScope = strings.Join(client.GetScopes(), " ")
	}

	// Validate that the requested scope is allowed for this client
	if !h.validateClientScope(client, requestedScope) {
		utils.WriteInvalidScopeError(w, "Requested scope exceeds client permissions")
		return
	}

	// Generate access token (and store it)
	scopeSlice := strings.Fields(requestedScope)
	accessToken, err := auth.GenerateAccessToken(h.tokenStore, "", clientID, scopeSlice, time.Hour)
	if err != nil {
		utils.WriteServerError(w, "Failed to generate access token")
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        requestedScope,
	}

	// Generate refresh token if offline_access scope is requested
	// This is useful for long-running services that need refresh capabilities
	if strings.Contains(requestedScope, "offline_access") || strings.Contains(requestedScope, "refresh_token") {
		refreshToken, err := auth.GenerateRefreshToken(h.tokenStore, "", clientID, scopeSlice, 30*24*time.Hour)
		if err == nil {
			response["refresh_token"] = refreshToken
			log.Printf("✅ Refresh token issued for client credentials flow: %s", clientID)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)

	log.Printf("✅ Client credentials token issued for client: %s", clientID)
}

// HandleRefreshToken handles token refresh requests
func (h *TokenHandlers) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔄 Processing token refresh request")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, "invalid_request", "Failed to parse request")
		return
	}

	refreshToken := r.FormValue("refresh_token")
	scope := r.FormValue("scope")

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
	_, err = auth.AuthenticateClient(clientID, clientSecret, h.clientStore)
	if err != nil {
		log.Printf("❌ Client authentication failed for %s: %v", clientID, err)
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication failed")
		return
	}

	// Validate refresh token
	tokenInfo, err := auth.ValidateToken(h.tokenStore, refreshToken)
	if err != nil {
		utils.WriteErrorResponse(w, "invalid_grant", "Invalid or expired refresh token")
		return
	}

	// Verify token belongs to the client
	if tokenInfo.ClientID != clientID {
		utils.WriteErrorResponse(w, "invalid_grant", "Refresh token does not belong to client")
		return
	}

	// Handle scope parameter
	var requestedScopeSlice []string
	if scope != "" {
		// If scope is provided, it must be a subset of the original scope
		originalScope := strings.Join(tokenInfo.Scopes, " ")
		if !h.isScopeSubset(scope, originalScope) {
			utils.WriteErrorResponse(w, "invalid_scope", "Requested scope exceeds original scope")
			return
		}
		requestedScopeSlice = strings.Fields(scope)
	} else {
		requestedScopeSlice = tokenInfo.Scopes
	}

	// Generate new access token
	newAccessToken, err := auth.GenerateAccessToken(h.tokenStore, tokenInfo.UserID, clientID, requestedScopeSlice, time.Hour)
	if err != nil {
		log.Printf("❌ Error generating access token: %v", err)
		utils.WriteServerError(w, "Failed to generate access token")
		return
	}

	// Generate new refresh token
	newRefreshToken, err := auth.GenerateRefreshToken(h.tokenStore, tokenInfo.UserID, clientID, requestedScopeSlice, 24*time.Hour)
	if err != nil {
		log.Printf("❌ Error generating refresh token: %v", err)
		utils.WriteServerError(w, "Failed to generate refresh token")
		return
	}

	// Revoke old refresh token
	err = h.tokenStore.RevokeToken(refreshToken)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to revoke old refresh token: %v", err)
		// Continue anyway as new tokens are already issued
	}

	// Create response
	response := map[string]interface{}{
		"access_token":  newAccessToken,
		"token_type":    "Bearer",
		"expires_in":    3600, // 1 hour
		"refresh_token": newRefreshToken,
		"scope":         strings.Join(requestedScopeSlice, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Tokens refreshed for client: %s", clientID)
}

// Helper functions

// clientSupportsGrantType checks if a client supports a specific grant type
func (h *TokenHandlers) clientSupportsGrantType(client interface{}, grantType string) bool {
	// Try fosite.Arguments first (our client store)
	if c, ok := client.(interface{ GetGrantTypes() fosite.Arguments }); ok {
		for _, gt := range c.GetGrantTypes() {
			if gt == grantType {
				return true
			}
		}
		return false
	}
	// Fallback to []string interface
	if c, ok := client.(interface{ GetGrantTypes() []string }); ok {
		for _, gt := range c.GetGrantTypes() {
			if gt == grantType {
				return true
			}
		}
	}
	return false
}

// validateClientScope validates that requested scope is allowed for the client
func (h *TokenHandlers) validateClientScope(client interface{}, requestedScope string) bool {
	if requestedScope == "" {
		return true
	}

	if c, ok := client.(interface{ GetScopes() []string }); ok {
		clientScopes := c.GetScopes()
		requestedScopes := strings.Split(requestedScope, " ")

		for _, reqScope := range requestedScopes {
			if reqScope == "" {
				continue
			}
			found := false
			for _, clientScope := range clientScopes {
				if clientScope == reqScope {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// validateAudience validates the audience parameter for token exchange
func (h *TokenHandlers) validateAudience(clientID, audience string) bool {
	// Get client and check if the audience is in the client's allowed audiences
	client, err := h.clientStore.GetClient(nil, clientID)
	if err != nil {
		return false
	}

	// Use type switch to handle different client types
	switch c := client.(type) {
	case interface{ GetAudience() fosite.Arguments }:
		for _, aud := range c.GetAudience() {
			if aud == audience {
				return true
			}
		}
	default:
		// If client doesn't implement GetAudience, allow any audience for now
		// In production, you might want to be more restrictive
		return true
	}
	return false
}

// determineTokenExchangeScope determines the scope for token exchange
func (h *TokenHandlers) determineTokenExchangeScope(originalScope, requestedScope string) string {
	if requestedScope == "" {
		return originalScope
	}

	// For token exchange, we can be more permissive, but still validate
	if h.isScopeSubset(requestedScope, originalScope) {
		return requestedScope
	}

	// Return original scope if requested scope is invalid
	return originalScope
}

// isScopeSubset checks if requestedScope is a subset of originalScope
func (h *TokenHandlers) isScopeSubset(requestedScope, originalScope string) bool {
	if requestedScope == "" {
		return true
	}

	originalScopes := strings.Split(originalScope, " ")
	requestedScopes := strings.Split(requestedScope, " ")

	for _, reqScope := range requestedScopes {
		if reqScope == "" {
			continue
		}
		found := false
		for _, origScope := range originalScopes {
			if origScope == reqScope {
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
