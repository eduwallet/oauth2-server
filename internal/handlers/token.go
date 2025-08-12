package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/sirupsen/logrus"
)

// TokenHandler manages OAuth2 token requests
type TokenHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Configuration  *config.Config
	Log            *logrus.Logger
}

// TokenInfo contains information about a validated token
type TokenInfo struct {
	Subject   string
	Scopes    fosite.Arguments
	Audiences fosite.Arguments
	Extra     map[string]interface{}
	ExpiresAt int64
	IssuedAt  int64
	TokenType string
}

// TokenExchangeRequest represents a token exchange request
type TokenExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	SubjectTokenInfo   *TokenInfo
	ActorToken         string
	ActorTokenType     string
	ActorTokenInfo     *TokenInfo
	RequestedTokenType string
	Audience           fosite.Arguments
	Scopes             fosite.Arguments
	Resource           string
}

// TokenExchangeResponse represents a token exchange response
type TokenExchangeResponse struct {
	AccessToken     string
	IssuedTokenType string
	TokenType       string
	ExpiresIn       int64
	RefreshToken    string
	Scope           fosite.Arguments
	Extra           map[string]interface{}
}

// NewTokenHandler creates a new token handler
func NewTokenHandler(oauth2Provider fosite.OAuth2Provider, configuration *config.Config, log *logrus.Logger) *TokenHandler {
	return &TokenHandler{
		OAuth2Provider: oauth2Provider,
		Configuration:  configuration,
		Log:            log,
	}
}

// ServeHTTP handles token requests and routes to appropriate flow
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")

	// RFC8693 Token Exchange: Handle token exchange grant type
	if grantType == "urn:ietf:params:oauth:grant-type:token-exchange" {
		h.handleTokenExchange(w, r)
		return
	}

	// With fosite v0.49.0 and ComposeAllEnabled, fosite should handle device code grants natively
	// Let's remove the custom bridge and rely on fosite's native RFC 8628 support
	h.handleStandardTokenRequest(w, r)
}

func (h *TokenHandler) handleStandardTokenRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Debug: Log the request details for device code flow
	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	deviceCode := r.FormValue("device_code")

	// Extract client ID from Basic auth if not in form
	if clientID == "" {
		if username, _, ok := r.BasicAuth(); ok {
			clientID = username
			h.Log.Printf("🔑 Extracted client ID from Basic auth: %s", clientID)
		} else {
			h.Log.Printf("⚠️ No Basic auth found and no client_id in form")
		}
	} else {
		h.Log.Printf("🔑 Client ID from form: %s", clientID)
	}

	h.Log.Printf("🔍 Token request details - Grant Type: %s, Client ID: %s", grantType, clientID)
	if deviceCode != "" {
		h.Log.Printf("🔍 Device Code present: %s...", deviceCode[:20])
	}

	// Debug: Log all form values
	h.Log.Printf("📝 All form values: %v", r.Form)

	// Let fosite handle ALL token requests including device code flow
	accessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, r, &openid.DefaultSession{})
	if err != nil {
		h.Log.Printf("❌ Error creating access request: %v", err)
		h.Log.Printf("🔍 Request form data: %v", r.Form)
		h.Log.Printf("🔍 Request headers: Authorization present: %v", r.Header.Get("Authorization") != "")
		h.Log.Printf("🔍 Authorization header value: %s", r.Header.Get("Authorization"))

		// Check if this is a device code request specifically
		if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
			h.Log.Printf("🔍 Device code grant request failed, attempting custom device code bridge")

			// BRIDGE: Check if the device code exists in our custom storage
			// and manually create a token if it's authorized
			if h.handleCustomDeviceCodeBridge(w, r, deviceCode, clientID) {
				return // Bridge handled the request
			}

			h.Log.Printf("🔍 Device code: %s", deviceCode)
			h.Log.Printf("🔍 Client ID: %s", clientID)

			// Check if client exists and has correct grant types
			if fositeProvider, ok := h.OAuth2Provider.(*fosite.Fosite); ok {
				if client, clientErr := fositeProvider.Store.GetClient(ctx, clientID); clientErr == nil {
					h.Log.Printf("🔍 Client found: %s", client.GetID())
					h.Log.Printf("🔍 Client grant types: %v", client.GetGrantTypes())
					h.Log.Printf("🔍 Client has device_code grant: %v", client.GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:device_code"))
					h.Log.Printf("🔍 Client is public: %v", client.IsPublic())

					// Test client authentication specifically
					if !client.IsPublic() {
						h.Log.Printf("🔍 Client requires authentication - checking credentials")

						// Try to authenticate the client manually to see what's failing
						authClient, err := h.OAuth2Provider.(*fosite.Fosite).AuthenticateClient(ctx, r, r.Form)
						if err != nil {
							h.Log.Printf("❌ Client authentication failed: %v", err)
						} else {
							h.Log.Printf("✅ Client authentication succeeded: %s", authClient.GetID())
						}
					}
				} else {
					h.Log.Printf("❌ Client lookup failed: %v", clientErr)
				}
			}
		}

		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	} // Enhance session with user info for authorization code flow
	session := accessRequest.GetSession()
	if defaultSession, ok := session.(*openid.DefaultSession); ok {
		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			subject := h.extractUserFromAuthCode(accessRequest)
			defaultSession.Claims.Subject = subject
			// case "client_credentials":
			// 	defaultSession.Claims.Subject = clientID
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

// handleDeviceCodeGrant handles the device code grant type for token exchange
func (h *TokenHandler) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request) {
	// Let fosite handle the device code grant properly!
	// Based on the official fosite test, we should let fosite's standard flow handle this
	// The key insight: fosite already has device code grant support built-in

	h.Log.Printf("🔄 Delegating device code grant to fosite's standard flow")

	// Let fosite handle the device code grant through its standard mechanisms
	// This ensures proper token generation, storage, and introspection compatibility
	h.handleStandardTokenRequest(w, r)
}

// generateFositeTokens uses fosite's native token generation for compatibility
func (h *TokenHandler) generateFositeTokens(ctx context.Context, fositeProvider *fosite.Fosite, accessRequest fosite.AccessRequester) (map[string]interface{}, error) {
	// Use fosite's native token generation to create JWT tokens that work with introspection
	response, err := fositeProvider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access response: %w", err)
	}

	// Convert fosite response to map format
	result := map[string]interface{}{
		"access_token": response.GetAccessToken(),
		"token_type":   "Bearer",
		"expires_in":   3600, // Default to 1 hour
		"scope":        strings.Join(accessRequest.GetGrantedScopes(), " "),
	}

	h.Log.Printf("✅ Generated fosite-native tokens for device code bridge")
	return result, nil
}

// handleCustomDeviceCodeBridge bridges custom device authorization storage with fosite token handling
// This method checks our custom device authorization storage and manually issues tokens if the device is authorized
func (h *TokenHandler) handleCustomDeviceCodeBridge(w http.ResponseWriter, r *http.Request, deviceCode, clientID string) bool {
	h.Log.Printf("🌉 Attempting device code bridge for device code: %s", deviceCode)

	// Access our custom device authorization storage via the global variable
	// This is a temporary bridge until we fully integrate device auth with fosite
	deviceAuthsMutex.RLock()
	deviceAuth, exists := deviceAuths[deviceCode]
	deviceAuthsMutex.RUnlock()

	if !exists {
		h.Log.Printf("🔍 Device code not found in custom storage: %s", deviceCode)
		return false
	}

	// Check if device is authorized and has a user
	deviceAuth.Mutex.RLock()
	isUsed := deviceAuth.IsUsed
	userID := deviceAuth.UserID
	clientIDFromAuth := deviceAuth.ClientID
	scope := deviceAuth.Scope
	expiresAt := deviceAuth.ExpiresAt
	deviceAuth.Mutex.RUnlock()

	// Validate the device authorization
	if clientIDFromAuth != clientID {
		h.Log.Printf("🔍 Client ID mismatch: expected %s, got %s", clientIDFromAuth, clientID)
		return false
	}

	if time.Now().After(expiresAt) {
		h.Log.Printf("🔍 Device authorization expired")
		return false
	}

	if !isUsed {
		h.Log.Printf("🔍 Device not yet authorized by user")
		// Return authorization_pending error
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "authorization_pending",
			"error_description": "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
		})
		return true
	}

	if userID == "" {
		h.Log.Printf("🔍 Device authorized but no user ID")
		return false
	}

	h.Log.Printf("✅ Device code bridge: Found authorized device for user %s", userID)

	// Generate tokens manually using fosite-compatible approach
	ctx := r.Context()

	// Get the client to create a proper access request
	if fositeProvider, ok := h.OAuth2Provider.(*fosite.Fosite); ok {
		client, err := fositeProvider.Store.GetClient(ctx, clientID)
		if err != nil {
			h.Log.Printf("❌ Failed to get client: %v", err)
			return false
		}

		// Create a mock access request for token generation
		session := userSession("", userID, []string{})

		scopes := strings.Split(scope, " ")
		if len(scopes) == 0 {
			scopes = []string{"openid"}
		}

		// Create a minimal access request
		accessRequest := &fosite.AccessRequest{
			Request: fosite.Request{
				Client:         client,
				RequestedScope: fosite.Arguments(scopes),
				GrantedScope:   fosite.Arguments(scopes),
				Session:        session,
				RequestedAt:    time.Now(),
			},
		}

		// Generate tokens using fosite-compatible method
		if tokenResponse, err := h.generateFositeTokens(ctx, fositeProvider, accessRequest); err == nil {
			h.Log.Printf("✅ Device code bridge: Generated tokens for user %s", userID)

			// Mark device as used (consume it)
			deviceAuth.Mutex.Lock()
			deviceAuth.IsUsed = true
			deviceAuth.Mutex.Unlock()

			// Return the token response
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			json.NewEncoder(w).Encode(tokenResponse)
			return true
		} else {
			h.Log.Printf("❌ Failed to generate tokens: %v", err)
		}
	}

	return false
} // Helper methods for device code grant
func (h *TokenHandler) findDeviceAuth(deviceCode string) *DeviceAuth {
	// Access the shared deviceAuths map from the same package
	deviceAuthsMutex.RLock()
	defer deviceAuthsMutex.RUnlock()

	if auth, exists := deviceAuths[deviceCode]; exists {
		return auth
	}
	return nil
}

func (h *TokenHandler) writeTokenError(w http.ResponseWriter, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": errorDescription,
	})
}

// handleTokenExchange implements RFC8693 Token Exchange functionality
func (h *TokenHandler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.Log.Printf("🔄 RFC8693 Token Exchange request received")

	// Parse and validate token exchange parameters
	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")
	requestedTokenType := r.FormValue("requested_token_type")
	audience := r.FormValue("audience")
	scope := r.FormValue("scope")
	actorToken := r.FormValue("actor_token")
	actorTokenType := r.FormValue("actor_token_type")

	// Note: resource parameter is defined in RFC8693 but not used in this implementation
	_ = r.FormValue("resource") // Prevent unused variable error

	// Log the exchange request
	h.Log.Printf("📝 Token Exchange - Subject Token Type: %s, Requested Token Type: %s",
		subjectTokenType, requestedTokenType)
	if subjectToken != "" {
		h.Log.Printf("🔑 Subject Token: %s...", subjectToken[:min(20, len(subjectToken))])
	}

	// Validate required parameters
	if subjectToken == "" {
		h.writeTokenError(w, "invalid_request", "Missing subject_token parameter")
		return
	}
	if subjectTokenType == "" {
		h.writeTokenError(w, "invalid_request", "Missing subject_token_type parameter")
		return
	}

	// Validate subject token type
	if !h.isSupportedTokenType(subjectTokenType) {
		h.writeTokenError(w, "invalid_request", "Unsupported subject_token_type: "+subjectTokenType)
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(ctx, r)
	if err != nil {
		h.Log.Printf("❌ Client authentication failed: %v", err)
		h.writeTokenError(w, "invalid_client", "Client authentication failed")
		return
	}

	// Validate subject token
	subjectTokenInfo, err := h.validateToken(ctx, subjectToken, subjectTokenType, client)
	if err != nil {
		h.Log.Printf("❌ Subject token validation failed: %v", err)
		h.writeTokenError(w, "invalid_grant", "Subject token is invalid or expired")
		return
	}

	h.Log.Printf("✅ Subject token validated for user: %s", subjectTokenInfo.Subject)

	// Validate actor token if present
	var actorTokenInfo *TokenInfo
	if actorToken != "" {
		if actorTokenType == "" {
			h.writeTokenError(w, "invalid_request", "Missing actor_token_type when actor_token is provided")
			return
		}

		actorTokenInfo, err = h.validateToken(ctx, actorToken, actorTokenType, client)
		if err != nil {
			h.Log.Printf("❌ Actor token validation failed: %v", err)
			h.writeTokenError(w, "invalid_grant", "Actor token is invalid or expired")
			return
		}
		h.Log.Printf("✅ Actor token validated for user: %s", actorTokenInfo.Subject)
	}

	// Set default requested token type if not specified
	if requestedTokenType == "" {
		requestedTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	// Create new access token through fosite
	newTokens, err := h.exchangeForNewTokens(ctx, client, subjectTokenInfo, actorTokenInfo, audience, scope)
	if err != nil {
		h.Log.Printf("❌ Failed to create new tokens: %v", err)
		h.writeTokenError(w, "invalid_grant", "Failed to exchange tokens")
		return
	}

	// Build token exchange response
	response := map[string]interface{}{
		"access_token":      newTokens.AccessToken,
		"issued_token_type": requestedTokenType,
		"token_type":        "Bearer",
		"expires_in":        newTokens.ExpiresIn,
	}

	if newTokens.RefreshToken != "" {
		response["refresh_token"] = newTokens.RefreshToken
	}

	if scope != "" {
		response["scope"] = scope
	}

	// Log successful exchange
	h.Log.Printf("✅ Token exchange completed for subject: %s", subjectTokenInfo.Subject)

	// Return the response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// isSupportedTokenType checks if the token type is supported for exchange
func (h *TokenHandler) isSupportedTokenType(tokenType string) bool {
	supportedTypes := []string{
		"urn:ietf:params:oauth:token-type:access_token",
		"urn:ietf:params:oauth:token-type:refresh_token",
		"urn:ietf:params:oauth:token-type:id_token",
		"urn:ietf:params:oauth:token-type:jwt",
	}

	for _, supported := range supportedTypes {
		if tokenType == supported {
			return true
		}
	}
	return false
}

// authenticateClient authenticates the client for token exchange
func (h *TokenHandler) authenticateClient(ctx context.Context, r *http.Request) (fosite.Client, error) {
	if fositeProvider, ok := h.OAuth2Provider.(*fosite.Fosite); ok {
		return fositeProvider.AuthenticateClient(ctx, r, r.Form)
	}
	return nil, fmt.Errorf("unable to access fosite provider")
}

// validateToken validates a token and returns its information
func (h *TokenHandler) validateToken(ctx context.Context, token, tokenType string, client fosite.Client) (*TokenInfo, error) {
	switch tokenType {
	case "urn:ietf:params:oauth:token-type:access_token":
		return h.validateAccessToken(ctx, token, client)
	case "urn:ietf:params:oauth:token-type:refresh_token":
		return h.validateRefreshToken(ctx, token, client)
	default:
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}
}

// validateAccessToken validates an access token using fosite's introspection
func (h *TokenHandler) validateAccessToken(ctx context.Context, token string, client fosite.Client) (*TokenInfo, error) {
	// Use fosite's introspection to validate the token
	_, accessRequest, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &openid.DefaultSession{})
	if err != nil {
		return nil, fmt.Errorf("token introspection failed: %w", err)
	}

	return &TokenInfo{
		Subject:   accessRequest.GetSession().GetSubject(),
		Scopes:    accessRequest.GetGrantedScopes(),
		TokenType: "urn:ietf:params:oauth:token-type:access_token",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

// validateRefreshToken validates a refresh token
func (h *TokenHandler) validateRefreshToken(ctx context.Context, token string, client fosite.Client) (*TokenInfo, error) {
	// Use fosite's introspection to validate the refresh token
	_, refreshRequest, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.RefreshToken, &openid.DefaultSession{})
	if err != nil {
		return nil, fmt.Errorf("refresh token introspection failed: %w", err)
	}

	return &TokenInfo{
		Subject:   refreshRequest.GetSession().GetSubject(),
		Scopes:    refreshRequest.GetGrantedScopes(),
		TokenType: "urn:ietf:params:oauth:token-type:refresh_token",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

// exchangeForNewTokens creates new tokens for the token exchange
func (h *TokenHandler) exchangeForNewTokens(ctx context.Context, client fosite.Client, subjectTokenInfo, actorTokenInfo *TokenInfo, audience, scope string) (*TokenExchangeResponse, error) {
	// For now, create a simple access token using the existing utils function
	accessToken, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	response := &TokenExchangeResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // Default 1 hour
	}

	return response, nil
}
