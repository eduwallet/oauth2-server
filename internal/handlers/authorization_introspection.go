package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// AuthorizationIntrospectionHandler manages authorization introspection requests
type AuthorizationIntrospectionHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Config         *config.Config
	Log            *logrus.Logger
	Storage        store.Storage
	SecretManager  *store.SecretManager
}

// NewAuthorizationIntrospectionHandler creates a new authorization introspection handler
func NewAuthorizationIntrospectionHandler(oauth2Provider fosite.OAuth2Provider, config *config.Config, log *logrus.Logger, storage store.Storage, secretManager *store.SecretManager) *AuthorizationIntrospectionHandler {
	return &AuthorizationIntrospectionHandler{
		OAuth2Provider: oauth2Provider,
		Config:         config,
		Log:            log,
		Storage:        storage,
		SecretManager:  secretManager,
	}
}

// ServeHTTP handles authorization introspection requests
func (h *AuthorizationIntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ Failed to parse form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	accessToken := r.FormValue("access-token")
	if accessToken == "" {
		h.Log.Printf("❌ Missing access-token parameter")
		http.Error(w, "Missing access-token parameter", http.StatusBadRequest)
		return
	}

	// Extract client credentials from Basic Auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		h.Log.Printf("❌ Missing Basic Auth credentials")
		http.Error(w, "Client authentication required", http.StatusUnauthorized)
		return
	}

	// Validate client credentials
	client, err := h.Storage.GetClient(r.Context(), clientID)
	if err != nil {
		h.Log.Printf("❌ Unknown client: %s", clientID)
		http.Error(w, "Invalid client", http.StatusUnauthorized)
		return
	}

	if !utils.ValidateSecret(clientSecret, client.GetHashedSecret()) {
		h.Log.Printf("❌ Invalid client secret for client: %s", clientID)
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Introspect the token using Fosite but bypass client authorization by using privileged client context
	tokenDetails, err := h.introspectTokenWithPrivilegedAccess(accessToken)
	if err != nil {
		h.Log.Printf("❌ Failed to introspect token: %v", err)
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	// Check if token is active
	active, _ := tokenDetails["active"].(bool)
	if !active {
		h.Log.Printf("❌ Token is not active")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token-details": tokenDetails,
			"user-info":     nil,
		})
		return
	}

	// Get client ID from token details
	tokenClientID, ok := tokenDetails["client_id"].(string)
	if !ok {
		h.Log.Printf("❌ Token missing client_id")
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	// Check if the authenticated client is an audience of the token's client
	tokenClient, err := h.Storage.GetClient(r.Context(), tokenClientID)
	if err != nil {
		h.Log.Printf("❌ Failed to get token client: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	tokenAudiences := tokenClient.GetAudience()
	isAudience := false
	for _, audience := range tokenAudiences {
		if audience == clientID {
			isAudience = true
			break
		}
	}

	// Also allow privileged clients to introspect any token
	isPrivileged := clientID == h.Config.Security.PrivilegedClientID

	if !isAudience && !isPrivileged {
		h.Log.Printf("❌ Client %s is not an audience for token client %s and is not privileged", clientID, tokenClientID)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Call userinfo endpoint
	userinfoReq, err := http.NewRequest("GET", h.Config.Server.BaseURL+"/userinfo", nil)
	if err != nil {
		h.Log.Printf("❌ Failed to create userinfo request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	userinfoReq.Header.Set("Authorization", "Bearer "+accessToken)

	userinfoResp, err := http.DefaultClient.Do(userinfoReq)
	if err != nil {
		h.Log.Printf("❌ Failed to call userinfo: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer userinfoResp.Body.Close()

	var userInfo interface{}
	if err := json.NewDecoder(userinfoResp.Body).Decode(&userInfo); err != nil {
		h.Log.Printf("❌ Failed to parse userinfo response: %v", err)
		userInfo = nil
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token-details": tokenDetails,
		"user-info":     userInfo,
	})
}

// introspectTokenWithPrivilegedAccess performs token introspection by manually decoding HMAC tokens
func (h *AuthorizationIntrospectionHandler) introspectTokenWithPrivilegedAccess(tokenValue string) (map[string]interface{}, error) {
	// For HMAC tokens, manually decode and verify the signature
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		return map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}, nil
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}, nil
	}

	// Verify signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}, nil
	}

	message := parts[0] + "." + parts[1]
	expectedSignature := hmac.New(sha256.New, []byte(h.Config.Security.JWTSecret))
	expectedSignature.Write([]byte(message))
	expectedMAC := expectedSignature.Sum(nil)

	if !hmac.Equal(signature, expectedMAC) {
		return map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}, nil
	}

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}, nil
	}

	// Check if token is expired
	now := time.Now().Unix()
	var exp int64
	if expVal, ok := claims["exp"].(float64); ok {
		exp = int64(expVal)
	}

	active := exp == 0 || exp > now

	// Build introspection response
	response := map[string]interface{}{
		"active": active,
	}

	if active {
		// Add standard claims
		if sub, ok := claims["sub"].(string); ok {
			response["sub"] = sub
		}
		if iss, ok := claims["iss"].(string); ok {
			response["iss"] = iss
		}
		if aud, ok := claims["aud"].(string); ok {
			response["aud"] = aud
		}
		if clientId, ok := claims["client_id"].(string); ok {
			response["client_id"] = clientId
		}
		if scope, ok := claims["scope"].(string); ok {
			response["scope"] = scope
		}
		if tokenType, ok := claims["token_type"].(string); ok {
			response["token_type"] = tokenType
		}
		if exp > 0 {
			response["exp"] = exp
		}
		if iat, ok := claims["iat"].(float64); ok {
			response["iat"] = int64(iat)
		}
	}

	return response, nil
}
