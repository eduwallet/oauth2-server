package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/storage"
	"strings"
	"time"
)

// HandleToken handles OAuth2 token endpoint
func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "client_credentials":
		h.handleClientCredentialsGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.handleDeviceCodeGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		h.HandleTokenExchange(w, r)
	default:
		h.writeError(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
	}
}

func (h *Handlers) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		h.writeError(w, "invalid_request", "Missing authorization code", http.StatusBadRequest)
		return
	}

	authReq, err := h.Storage.GetAuthCode(code)
	if err != nil {
		h.writeError(w, "invalid_grant", "Invalid authorization code", http.StatusBadRequest)
		return
	}

	accessToken := generateRandomString(64)
	refreshToken := generateRandomString(64)

	accessTokenInfo := &storage.TokenInfo{
		Token:     accessToken,
		TokenType: "access_token",
		ClientID:  authReq.ClientID,
		UserID:    authReq.UserID,
		Scopes:    authReq.Scopes,
		Audience:  []string{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.TokenExpirySeconds) * time.Second),
		Active:    true,
		Extra:     make(map[string]interface{}),
	}

	if err := h.Storage.StoreToken(accessTokenInfo); err != nil {
		h.Logger.WithError(err).Error("Failed to store access token")
		h.writeError(w, "server_error", "Failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshTokenInfo := &storage.TokenInfo{
		Token:     refreshToken,
		TokenType: "refresh_token",
		ClientID:  authReq.ClientID,
		UserID:    authReq.UserID,
		Scopes:    authReq.Scopes,
		Audience:  []string{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.RefreshTokenExpirySeconds) * time.Second),
		Active:    true,
		Extra:     make(map[string]interface{}),
	}

	if err := h.Storage.StoreToken(refreshTokenInfo); err != nil {
		h.Logger.WithError(err).Error("Failed to store refresh token")
		h.writeError(w, "server_error", "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.Config.Security.TokenExpirySeconds,
		RefreshToken: refreshToken,
	}

	h.writeTokenResponse(w, response)
}

func (h *Handlers) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID, _, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
	}

	if clientID == "" {
		h.writeError(w, "invalid_request", "Missing client_id", http.StatusBadRequest)
		return
	}

	accessToken := generateRandomString(64)
	scope := r.FormValue("scope")

	accessTokenInfo := &storage.TokenInfo{
		Token:     accessToken,
		TokenType: "access_token",
		ClientID:  clientID,
		UserID:    clientID,
		Scopes:    strings.Fields(scope),
		Audience:  []string{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.TokenExpirySeconds) * time.Second),
		Active:    true,
		Extra:     make(map[string]interface{}),
	}

	if err := h.Storage.StoreToken(accessTokenInfo); err != nil {
		h.Logger.WithError(err).Error("Failed to store access token")
		h.writeError(w, "server_error", "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   h.Config.Security.TokenExpirySeconds,
	}

	h.writeTokenResponse(w, response)
}

func (h *Handlers) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		h.writeError(w, "invalid_request", "Missing refresh_token", http.StatusBadRequest)
		return
	}

	requestedScope := r.FormValue("scope")

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		h.writeError(w, "invalid_client", "Client authentication required", http.StatusUnauthorized)
		return
	}

	client := h.findClient(clientID)
	if client == nil {
		h.writeError(w, "invalid_client", "Unknown client", http.StatusUnauthorized)
		return
	}

	if !client.Public && client.ClientSecret != clientSecret {
		h.writeError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	tokenInfo, err := h.Storage.GetToken(refreshToken)
	if err != nil {
		h.writeError(w, "invalid_grant", "Invalid refresh token", http.StatusBadRequest)
		return
	}

	if tokenInfo.TokenType != "refresh_token" {
		h.writeError(w, "invalid_grant", "Token is not a refresh token", http.StatusBadRequest)
		return
	}

	if tokenInfo.ExpiresAt.Before(time.Now()) || !tokenInfo.Active {
		h.writeError(w, "invalid_grant", "Refresh token expired or inactive", http.StatusBadRequest)
		return
	}

	// RFC 6749 + OAuth2 Security Best Practices:
	// Allow refresh token usage if:
	// 1. The client is the original issuer, OR
	// 2. The client is listed in the token's audience
	if !isClientAuthorizedToUseRefreshToken(clientID, tokenInfo) {
		h.writeError(w, "invalid_grant", "Client not authorized to use this refresh token", http.StatusBadRequest)
		return
	}

	var newScopes []string
	if requestedScope != "" {
		requestedScopes := strings.Fields(requestedScope)
		for _, requested := range requestedScopes {
			for _, original := range tokenInfo.Scopes {
				if requested == original {
					newScopes = append(newScopes, requested)
					break
				}
			}
		}
	} else {
		newScopes = tokenInfo.Scopes
	}

	newAccessToken := generateRandomString(64)
	newRefreshToken := generateRandomString(64)

	accessTokenInfo := &storage.TokenInfo{
		Token:     newAccessToken,
		TokenType: "access_token",
		ClientID:  clientID,
		UserID:    tokenInfo.UserID,
		Scopes:    newScopes,
		Audience:  tokenInfo.Audience,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.TokenExpirySeconds) * time.Second),
		Active:    true,
		Extra:     make(map[string]interface{}),
	}

	if err := h.Storage.StoreToken(accessTokenInfo); err != nil {
		h.Logger.WithError(err).Error("Failed to store new access token")
		h.writeError(w, "server_error", "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshTokenInfo := &storage.TokenInfo{
		Token:     newRefreshToken,
		TokenType: "refresh_token",
		ClientID:  clientID,
		UserID:    tokenInfo.UserID,
		Scopes:    newScopes,
		Audience:  tokenInfo.Audience,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.RefreshTokenExpirySeconds) * time.Second),
		Active:    true,
		Extra:     make(map[string]interface{}),
	}

	if err := h.Storage.StoreToken(refreshTokenInfo); err != nil {
		h.Logger.WithError(err).Error("Failed to store new refresh token")
		h.writeError(w, "server_error", "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	if err := h.Storage.DeleteToken(refreshToken); err != nil {
		h.Logger.WithError(err).Warn("Failed to revoke old refresh token")
	}

	response := TokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.Config.Security.TokenExpirySeconds,
		RefreshToken: newRefreshToken,
		Scope:        strings.Join(newScopes, " "),
	}

	h.Logger.Debugf("Refresh token grant successful for client %s, user %s", clientID, tokenInfo.UserID)
	h.writeTokenResponse(w, response)
}

func (h *Handlers) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		h.writeError(w, "invalid_request", "Missing device_code", http.StatusBadRequest)
		return
	}

	deviceState, err := h.Storage.GetDeviceCode(deviceCode)
	if err != nil {
		h.writeError(w, "invalid_grant", "Invalid device_code", http.StatusBadRequest)
		return
	}

	if time.Since(deviceState.CreatedAt) > time.Duration(deviceState.ExpiresIn)*time.Second {
		h.writeError(w, "expired_token", "Device code has expired", http.StatusBadRequest)
		return
	}

	if !deviceState.Authorized {
		h.writeError(w, "authorization_pending", "User has not yet authorized the device", http.StatusBadRequest)
		return
	}

	accessToken := generateRandomString(64)
	refreshToken := generateRandomString(64)

	accessTokenInfo := &storage.TokenInfo{
		Token:     accessToken,
		TokenType: "access_token",
		ClientID:  deviceState.ClientID,
		UserID:    deviceState.UserID,
		Scopes:    deviceState.Scopes,
		Audience:  []string{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.TokenExpirySeconds) * time.Second),
		Active:    true,
		Extra:     make(map[string]interface{}),
	}

	if err := h.Storage.StoreToken(accessTokenInfo); err != nil {
		h.Logger.WithError(err).Error("Failed to store access token")
		h.writeError(w, "server_error", "Failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshTokenInfo := &storage.TokenInfo{
		Token:     refreshToken,
		TokenType: "refresh_token",
		ClientID:  deviceState.ClientID,
		UserID:    deviceState.UserID,
		Scopes:    deviceState.Scopes,
		Audience:  []string{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.RefreshTokenExpirySeconds) * time.Second),
		Active:    true,
		Extra:     make(map[string]interface{}),
	}

	if err := h.Storage.StoreToken(refreshTokenInfo); err != nil {
		h.Logger.WithError(err).Error("Failed to store refresh token")
		h.writeError(w, "server_error", "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	h.Storage.DeleteDeviceCode(deviceCode)

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.Config.Security.TokenExpirySeconds,
		RefreshToken: refreshToken,
		Scope:        strings.Join(deviceState.Scopes, " "),
	}

	h.writeTokenResponse(w, response)
}

// HandleRevoke handles token revocation
func (h *Handlers) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.writeError(w, "invalid_request", "Missing token parameter", http.StatusBadRequest)
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		h.writeError(w, "invalid_client", "Client authentication required", http.StatusUnauthorized)
		return
	}

	client := h.findClient(clientID)
	if client == nil {
		h.writeError(w, "invalid_client", "Unknown client", http.StatusUnauthorized)
		return
	}

	if !client.Public && client.ClientSecret != clientSecret {
		h.writeError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	if err := h.Storage.DeleteToken(token); err != nil {
		h.Logger.WithError(err).Debug("Token revocation failed (token may not exist)")
	}

	w.WriteHeader(http.StatusOK)
}

// HandleIntrospect handles token introspection
func (h *Handlers) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.writeError(w, "invalid_request", "Missing token parameter", http.StatusBadRequest)
		return
	}

	tokenTypeHint := r.FormValue("token_type_hint")
	h.Logger.Debugf("Token introspection request: token=%s..., hint=%s", token[:min(8, len(token))], tokenTypeHint)

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		h.writeError(w, "invalid_client", "Client authentication required", http.StatusUnauthorized)
		return
	}

	client := h.findClient(clientID)
	if client == nil {
		h.writeError(w, "invalid_client", "Unknown client", http.StatusUnauthorized)
		return
	}

	if !client.Public && client.ClientSecret != clientSecret {
		h.writeError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	h.Logger.Debugf("Client %s authenticated for token introspection", clientID)

	tokenInfo, err := h.Storage.GetToken(token)
	if err != nil {
		h.Logger.Debugf("Token validation failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	if tokenInfo.ExpiresAt.Before(time.Now()) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	response := map[string]interface{}{
		"active":    true,
		"client_id": tokenInfo.ClientID,
		"exp":       tokenInfo.ExpiresAt.Unix(),
		"iat":       tokenInfo.IssuedAt.Unix(),
		"sub":       tokenInfo.UserID,
	}

	if tokenInfo.UserID != "" {
		response["username"] = tokenInfo.UserID
	}

	if len(tokenInfo.Scopes) > 0 {
		response["scope"] = tokenInfo.Scopes
	}

	if len(tokenInfo.Audience) > 0 {
		response["aud"] = tokenInfo.Audience
	}

	if tokenInfo.Issuer != "" {
		response["iss"] = tokenInfo.Issuer
	}

	if tokenTypeHint != "" && tokenTypeHint == tokenInfo.TokenType {
		response["token_type"] = tokenTypeHint
	}

	h.Logger.Debugf("Token introspection successful for client %s, token from client %s", clientID, tokenInfo.ClientID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(response)
}

// HandleTokenExchange handles token exchange requests
func (h *Handlers) HandleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		h.writeError(w, "unsupported_grant_type", "Grant type not supported", http.StatusBadRequest)
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" {
		h.writeError(w, "invalid_client", "Client authentication required", http.StatusUnauthorized)
		return
	}

	client := h.findClient(clientID)
	if client == nil {
		h.writeError(w, "invalid_client", "Unknown client", http.StatusUnauthorized)
		return
	}

	if !client.Public && client.ClientSecret != clientSecret {
		h.writeError(w, "invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")
	requestedTokenType := r.FormValue("requested_token_type")
	audience := r.FormValue("audience")
	requestedScope := r.FormValue("scope")

	if subjectToken == "" || subjectTokenType == "" {
		h.writeError(w, "invalid_request", "Missing required token exchange parameters", http.StatusBadRequest)
		return
	}

	validSubjectTokenTypes := []string{
		"urn:ietf:params:oauth:token-type:access_token",
		"urn:ietf:params:oauth:token-type:refresh_token",
		"urn:ietf:params:oauth:token-type:id_token",
	}

	isValidSubjectType := false
	for _, validType := range validSubjectTokenTypes {
		if subjectTokenType == validType {
			isValidSubjectType = true
			break
		}
	}

	if !isValidSubjectType {
		h.writeError(w, "invalid_request", "Unsupported subject_token_type", http.StatusBadRequest)
		return
	}

	tokenInfo, err := h.Storage.GetToken(subjectToken)
	if err != nil {
		h.Logger.Debugf("Token validation failed: %v", err)
		h.writeError(w, "invalid_grant", "Invalid or expired subject token", http.StatusBadRequest)
		return
	}

	if tokenInfo.ExpiresAt.Before(time.Now()) {
		h.writeError(w, "invalid_grant", "Subject token has expired", http.StatusBadRequest)
		return
	}

	// RFC 8693: Check if the requesting client is authorized to exchange this token
	// This is based on authorization server policy, not token audience inheritance
	if !isClientAuthorizedForTokenExchange(clientID, tokenInfo, h.Config) {
		h.writeError(w, "invalid_grant", "Client not authorized to exchange this token", http.StatusBadRequest)
		return
	}

	// RFC 8693: Validate requested audience based on client authorization policy
	if audience != "" {
		if !isClientAuthorizedForAudience(clientID, audience, h.Config) {
			h.writeError(w, "invalid_target", "Client not authorized for requested audience", http.StatusBadRequest)
			return
		}
	}

	originalScope := tokenInfo.Scopes
	scopeSlice := determineTokenExchangeScope(originalScope, strings.Fields(requestedScope))

	if requestedTokenType == "" {
		requestedTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	var issuedToken string
	var issuedTokenType string
	var expiresIn int

	switch requestedTokenType {
	case "urn:ietf:params:oauth:token-type:refresh_token":
		issuedToken = generateRandomString(64)
		issuedTokenType = "refresh_token"
		expiresIn = h.Config.Security.RefreshTokenExpirySeconds

		tokenInfo := &storage.TokenInfo{
			Token:     issuedToken,
			TokenType: "refresh_token",
			ClientID:  clientID,
			UserID:    tokenInfo.UserID,
			Scopes:    scopeSlice,
			Audience:  []string{audience},
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
			Active:    true,
			Extra:     make(map[string]interface{}),
		}

		if err := h.Storage.StoreToken(tokenInfo); err != nil {
			h.Logger.WithError(err).Error("Failed to store refresh token")
			h.writeError(w, "server_error", "Failed to generate token", http.StatusInternalServerError)
			return
		}

	case "urn:ietf:params:oauth:token-type:access_token":
		fallthrough
	default:
		issuedToken = generateRandomString(64)
		issuedTokenType = "access_token"
		expiresIn = h.Config.Security.TokenExpirySeconds

		tokenInfoStruct := &storage.TokenInfo{
			Token:     issuedToken,
			TokenType: "access_token",
			ClientID:  clientID,
			UserID:    tokenInfo.UserID,
			Scopes:    scopeSlice,
			Audience:  []string{audience},
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
			Active:    true,
			Extra:     make(map[string]interface{}),
		}

		if err := h.Storage.StoreToken(tokenInfoStruct); err != nil {
			h.Logger.WithError(err).Error("Failed to store access token")
			h.writeError(w, "server_error", "Failed to generate token", http.StatusInternalServerError)
			return
		}
	}

	response := map[string]interface{}{
		issuedTokenType:     issuedToken,
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
		"issued_token_type": requestedTokenType,
	}

	if len(scopeSlice) > 0 {
		response["scope"] = scopeSlice
	}

	if audience != "" {
		response["audience"] = audience
	}

	h.Logger.Debugf("Token exchange successful: client=%s, subject_token_type=%s, issued_token_type=%s",
		clientID, subjectTokenType, requestedTokenType)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}
