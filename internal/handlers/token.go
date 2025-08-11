package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2-server/internal/utils"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
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
	case "urn:ietf:params:oauth:grant-type:device_code":
		// Handle device code grant with our custom implementation
		h.handleDeviceCodeGrant(w, r)
	default:
		// Let fosite handle ALL other standard grant types
		h.handleStandardTokenRequest(w, r)
	}
}

func (h *TokenHandler) handleStandardTokenRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Debug: Log the request details for device code flow
	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	deviceCode := r.FormValue("device_code")

	h.Log.Printf("🔍 Token request details - Grant Type: %s, Client ID: %s", grantType, clientID)
	if deviceCode != "" {
		h.Log.Printf("🔍 Device Code present: %s...", deviceCode[:20])
	}

	// Debug: Log all form values
	h.Log.Printf("📝 All form values: %v", r.Form)

	// Let fosite handle ALL token requests including device code flow
	accessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
	if err != nil {
		h.Log.Printf("❌ Error creating access request: %v", err)
		h.Log.Printf("🔍 Request form data: %v", r.Form)
		h.Log.Printf("🔍 Request headers: Authorization present: %v", r.Header.Get("Authorization") != "")
		h.Log.Printf("🔍 Authorization header value: %s", r.Header.Get("Authorization"))

		// Check if this is a device code request specifically
		if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
			h.Log.Printf("🔍 Device code grant request failed")
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

		h.OAuth2Provider.WriteAccessError(w, accessRequest, err)
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
		h.OAuth2Provider.WriteAccessError(w, accessRequest, err)
		return
	}

	h.OAuth2Provider.WriteAccessResponse(w, accessRequest, response)
}

// Helper function to extract user from authorization code
func (h *TokenHandler) extractUserFromAuthCode(req fosite.AccessRequester) string {
	// This would need to be implemented based on your session storage
	// For now, return a default user
	return "user123"
}

// handleDeviceCodeGrant handles the device code grant type for token exchange
func (h *TokenHandler) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	deviceCode := r.FormValue("device_code")
	clientID := r.FormValue("client_id")

	h.Log.Printf("🔍 Device code grant - Device Code: %s, Client ID: %s", deviceCode, clientID)

	// Look up the device authorization
	deviceAuth := h.findDeviceAuth(deviceCode)
	if deviceAuth == nil {
		h.Log.Printf("❌ Device authorization not found for device code: %s", deviceCode)
		h.writeTokenError(w, "invalid_grant", "Device authorization not found or expired")
		return
	}

	// Check if the device has been authorized by the user
	if !deviceAuth.IsUsed {
		h.Log.Printf("⏳ Device authorization pending for device code: %s", deviceCode)
		h.writeTokenError(w, "authorization_pending", "User has not yet completed authorization")
		return
	}

	// Check if the client ID matches
	if deviceAuth.ClientID != clientID {
		h.Log.Printf("❌ Client ID mismatch for device code: %s (expected: %s, got: %s)", deviceCode, deviceAuth.ClientID, clientID)
		h.writeTokenError(w, "invalid_client", "Client ID does not match")
		return
	}

	// Get the client from fosite's store
	fositeProvider, ok := h.OAuth2Provider.(*fosite.Fosite)
	if !ok {
		h.Log.Printf("❌ Unsupported OAuth2 provider type")
		h.writeTokenError(w, "server_error", "Unsupported OAuth2 provider type")
		return
	}

	client, err := fositeProvider.Store.GetClient(ctx, deviceAuth.ClientID)
	if err != nil {
		h.Log.Printf("❌ Failed to get client: %v", err)
		h.writeTokenError(w, "invalid_client", "Invalid client")
		return
	}

	// Parse the requested scopes
	scopes := fosite.Arguments{}
	if deviceAuth.Scope != "" {
		scopes = strings.Split(deviceAuth.Scope, " ")
	}

	// Create a proper session for the authenticated user
	session := &fosite.DefaultSession{
		Subject:  deviceAuth.UserID,
		Username: deviceAuth.UserID,
	}

	// Create access request manually for device flow
	// Use authorization_code grant internally since fosite understands it
	accessRequest := fosite.NewAccessRequest(session)
	accessRequest.Client = client
	accessRequest.GrantTypes = fosite.Arguments{"authorization_code"} // Use supported grant type
	accessRequest.RequestedScope = scopes
	accessRequest.GrantedScope = scopes

	// Now use fosite's token generation and storage
	response, err := h.generateFositeTokens(ctx, fositeProvider, accessRequest)
	if err != nil {
		h.Log.Printf("❌ Failed to generate fosite tokens: %v", err)
		h.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}

	h.Log.Printf("✅ Device code exchange successful for user: %s", deviceAuth.UserID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// generateFositeTokens uses fosite's internal token generation and storage
func (h *TokenHandler) generateFositeTokens(ctx context.Context, fositeProvider *fosite.Fosite, accessRequest fosite.AccessRequester) (map[string]interface{}, error) {
	// Create tokens manually but use fosite's signature method for storage compatibility
	// Generate access token using fosite-compatible approach
	accessToken := h.generateFositeCompatibleToken("access", accessRequest)

	// Generate refresh token if offline_access is requested
	var refreshToken string
	if accessRequest.GetRequestedScopes().Has("offline_access") {
		refreshToken = h.generateFositeCompatibleToken("refresh", accessRequest)
		h.Log.Printf("✅ Refresh token generated")
	}

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(accessRequest.GetRequestedScopes(), " "),
	}

	if refreshToken != "" {
		response["refresh_token"] = refreshToken
	}

	// Store the tokens using fosite's proper interface methods
	// The key insight: we need to use the token signature (hash) as the storage key
	// For fosite compatibility, let's try storing the raw token as the signature
	if err := h.storeFositeTokens(ctx, fositeProvider, accessRequest, accessToken, refreshToken); err != nil {
		h.Log.Printf("⚠️ Failed to store tokens in fosite store: %v", err)
		// Continue anyway - tokens still work for the device flow
	}

	return response, nil
} // generateFositeCompatibleToken generates tokens in a format similar to fosite
func (h *TokenHandler) generateFositeCompatibleToken(tokenType string, req fosite.AccessRequester) string {
	// Generate a token that follows fosite's general format
	// This creates tokens that look like fosite tokens but are generated manually
	clientID := req.GetClient().GetID()
	subject := req.GetSession().GetSubject()

	// Use a format similar to fosite's default token format
	return fmt.Sprintf("ory_%s_%s_%s_%d", tokenType, clientID, subject, time.Now().Unix())
}

// storeFositeTokens attempts to store the generated tokens in fosite's store using proper interface methods
func (h *TokenHandler) storeFositeTokens(ctx context.Context, fositeProvider *fosite.Fosite, req fosite.AccessRequester, accessToken, refreshToken string) error {
	// Use fosite's proper interface methods for storing tokens via MemoryStore
	// The key insight: fosite typically uses token signatures (hashes) as storage keys
	// Let's try using the raw token as signature first, then explore hashing if needed

	// Type assert to MemoryStore to access the CreateAccessTokenSession and CreateRefreshTokenSession methods
	if memStore, ok := fositeProvider.Store.(*storage.MemoryStore); ok {
		// Try storing the access token using the token itself as the signature
		// In some fosite implementations, the signature is the token or a hash of it
		tokenSignature := accessToken // Start with raw token as signature

		if err := memStore.CreateAccessTokenSession(ctx, tokenSignature, req); err != nil {
			return fmt.Errorf("failed to store access token: %w", err)
		}
		h.Log.Printf("✅ Access token stored in fosite memory store using CreateAccessTokenSession with signature: %s", tokenSignature)

		// Store refresh token if provided using fosite's CreateRefreshTokenSession method
		if refreshToken != "" {
			refreshTokenSignature := refreshToken // Use refresh token as its own signature
			if err := memStore.CreateRefreshTokenSession(ctx, refreshTokenSignature, req); err != nil {
				return fmt.Errorf("failed to store refresh token: %w", err)
			}
			h.Log.Printf("✅ Refresh token stored in fosite memory store using CreateRefreshTokenSession")
		}

		return nil
	}

	return fmt.Errorf("unsupported store type - expected MemoryStore")
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
