package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/sirupsen/logrus"
)

// AuthorizationIntrospectionHandler manages authorization introspection requests
type AuthorizationIntrospectionHandler struct {
	OAuth2Provider              fosite.OAuth2Provider
	Config                      *config.Config
	Log                         *logrus.Logger
	Storage                     store.Storage
	SecretManager               *store.SecretManager
	PrivilegedClientSecrets     map[string]string
	AccessTokenToIssuerStateMap *map[string]string
}

// NewAuthorizationIntrospectionHandler creates a new authorization introspection handler
func NewAuthorizationIntrospectionHandler(oauth2Provider fosite.OAuth2Provider, config *config.Config, log *logrus.Logger, storage store.Storage, secretManager *store.SecretManager, privilegedClientSecrets map[string]string, accessTokenToIssuerStateMap *map[string]string) *AuthorizationIntrospectionHandler {
	return &AuthorizationIntrospectionHandler{
		OAuth2Provider:              oauth2Provider,
		Config:                      config,
		Log:                         log,
		Storage:                     storage,
		SecretManager:               secretManager,
		PrivilegedClientSecrets:     privilegedClientSecrets,
		AccessTokenToIssuerStateMap: accessTokenToIssuerStateMap,
	}
}

// ServeHTTP handles authorization introspection requests
func (h *AuthorizationIntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("🔍 AuthorizationIntrospectionHandler.ServeHTTP called")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.Log.Errorf("❌ Failed to parse form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	accessToken := r.FormValue("access-token")
	if accessToken == "" {
		h.Log.Errorf("❌ Missing access-token parameter")
		http.Error(w, "Missing access-token parameter", http.StatusBadRequest)
		return
	}

	// Extract client credentials from Basic Auth
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		h.Log.Errorf("❌ Missing Basic Auth credentials")
		http.Error(w, "Client authentication required", http.StatusUnauthorized)
		return
	}

	// Validate client credentials
	client, err := h.Storage.GetClient(r.Context(), clientID)
	if err != nil {
		h.Log.Errorf("❌ Unknown client: %s", clientID)
		http.Error(w, "Invalid client", http.StatusUnauthorized)
		return
	}

	if !utils.ValidateSecret(clientSecret, client.GetHashedSecret()) {
		h.Log.Errorf("❌ Invalid client secret for client: %s", clientID)
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Introspect the token using Fosite but bypass client authorization by using privileged client context
	tokenDetails, err := h.introspectTokenWithPrivilegedAccess(accessToken)
	if err != nil {
		h.Log.Errorf("❌ Failed to introspect token: %v", err)
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	h.Log.Printf("✅ Token introspected successfully: %+v", tokenDetails)
	// Check if token is active
	active, _ := tokenDetails["active"].(bool)
	if !active {
		h.Log.Errorf("❌ Token is not active")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token_details": tokenDetails,
			"user_info":     nil,
		})
		return
	}

	// Get client ID from token details
	tokenClientID, ok := tokenDetails["client_id"].(string)
	if !ok {
		h.Log.Errorf("❌ Token missing client_id")
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	// Check if the authenticated client is an audience of the token's client
	tokenClient, err := h.Storage.GetClient(r.Context(), tokenClientID)
	if err != nil {
		h.Log.Errorf("❌ Failed to get token client: %v", err)
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
		h.Log.Errorf("❌ Client %s is not an audience for token client %s and is not privileged", clientID, tokenClientID)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Call userinfo endpoint
	userinfoReq, err := http.NewRequest("GET", h.Config.Server.BaseURL+"/userinfo", nil)
	if err != nil {
		h.Log.Errorf("❌ Failed to create userinfo request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	userinfoReq.Header.Set("Authorization", "Bearer "+accessToken)

	userinfoResp, err := http.DefaultClient.Do(userinfoReq)
	if err != nil {
		h.Log.Errorf("❌ Failed to call userinfo: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer userinfoResp.Body.Close()

	var userInfo interface{}
	if err := json.NewDecoder(userinfoResp.Body).Decode(&userInfo); err != nil {
		h.Log.Errorf("❌ Failed to parse userinfo response: %v", err)
		userInfo = nil
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token_details": tokenDetails,
		"user_info":     userInfo,
	})
}

// introspectTokenWithPrivilegedAccess performs token introspection using Fosite with privileged access
func (h *AuthorizationIntrospectionHandler) introspectTokenWithPrivilegedAccess(tokenValue string) (map[string]interface{}, error) {
	previewLen := 20
	if len(tokenValue) < previewLen {
		previewLen = len(tokenValue)
	}
	h.Log.Printf("🔍 Starting privileged introspection for token: %s", tokenValue[:previewLen]+"...")

	// Create a local introspection request that Fosite can handle
	form := make(url.Values)
	form.Set("token", tokenValue)

	req, err := http.NewRequest("POST", h.Config.Server.BaseURL+"/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		h.Log.Errorf("❌ Failed to create HTTP request: %v", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = form

	// Use privileged client credentials to bypass audience restrictions
	privilegedClientID := h.Config.Security.PrivilegedClientID
	if privilegedClientID == "" {
		h.Log.Errorf("❌ No privileged client configured")
		return nil, fmt.Errorf("no privileged client configured")
	}

	h.Log.Printf("🔍 Privileged client ID: %s", privilegedClientID)

	// Get the privileged client's plain text secret from the handler's map
	privilegedClientSecret, exists := h.PrivilegedClientSecrets[privilegedClientID]
	if !exists {
		h.Log.Errorf("❌ Privileged client secret not found for client: %s", privilegedClientID)
		h.Log.Printf("🔍 Available secrets: %v", h.PrivilegedClientSecrets)
		return nil, fmt.Errorf("privileged client secret not found for client: %s", privilegedClientID)
	}

	h.Log.Printf("✅ Found privileged client secret, length: %d", len(privilegedClientSecret))

	// Set basic auth with privileged client credentials
	req.SetBasicAuth(privilegedClientID, privilegedClientSecret)
	h.Log.Printf("🔍 Set basic auth for privileged client")

	// Create the introspection request using Fosite
	ctx := req.Context()
	h.Log.Printf("🔍 Calling NewIntrospectionRequest...")
	ir, err := h.OAuth2Provider.NewIntrospectionRequest(ctx, req, &openid.DefaultSession{})
	if err != nil {
		h.Log.Errorf("❌ Error creating privileged introspection request: %v", err)
		return map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}, nil
	}

	h.Log.Printf("✅ Privileged introspection request created successfully")

	// Capture the response
	responseCapture := &authResponseCapture{
		statusCode: 200,
		header:     make(http.Header),
		body:       bytes.Buffer{},
	}
	h.Log.Printf("🔍 Writing introspection response...")
	h.OAuth2Provider.WriteIntrospectionResponse(ctx, responseCapture, ir)

	h.Log.Printf("✅ Introspection response written, status: %d, body length: %d", responseCapture.statusCode, responseCapture.body.Len())

	// Parse the response
	var response map[string]interface{}
	if err := json.Unmarshal(responseCapture.body.Bytes(), &response); err != nil {
		h.Log.Errorf("❌ Failed to parse introspection response: %v", err)
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	// Add issuer_state from map if not present in response
	if _, hasIssuerState := response["issuer_state"]; !hasIssuerState {
		h.Log.Printf("🔍 Looking up issuer_state for token: %s", tokenValue[:20])
		if h.AccessTokenToIssuerStateMap != nil {
			h.Log.Printf("🔍 Map has %d entries", len(*h.AccessTokenToIssuerStateMap))
			if issuerState, exists := (*h.AccessTokenToIssuerStateMap)[tokenValue]; exists {
				response["issuer_state"] = issuerState
				h.Log.Printf("✅ Added issuer_state from map to introspection response: %v", issuerState)
			} else {
				h.Log.Printf("⚠️ issuer_state not found in map for token")
			}
		} else {
			h.Log.Printf("⚠️ AccessTokenToIssuerStateMap is nil")
		}
	} else {
		h.Log.Printf("ℹ️ issuer_state already present in response")
	}

	h.Log.Printf("✅ Privileged introspection completed successfully, active: %v", response["active"])
	return response, nil
}

// authResponseCapture implements http.ResponseWriter to capture Fosite responses
type authResponseCapture struct {
	statusCode int
	header     http.Header
	body       bytes.Buffer
}

func (rc *authResponseCapture) Header() http.Header {
	return rc.header
}

func (rc *authResponseCapture) Write(data []byte) (int, error) {
	return rc.body.Write(data)
}

func (rc *authResponseCapture) WriteHeader(statusCode int) {
	rc.statusCode = statusCode
}
