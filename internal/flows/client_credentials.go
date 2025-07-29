package flows

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"oauth2-server/internal/auth"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// ClientCredentialsFlow handles the client credentials flow
type ClientCredentialsFlow struct {
	clientStore *store.ClientStore
	tokenStore  *store.TokenStore
	config      *config.Config
}

// NewClientCredentialsFlow creates a new client credentials flow handler
func NewClientCredentialsFlow(clientStore *store.ClientStore, tokenStore *store.TokenStore, cfg *config.Config) *ClientCredentialsFlow {
	return &ClientCredentialsFlow{
		clientStore: clientStore,
		tokenStore:  tokenStore,
		config:      cfg,
	}
}

// Handle processes client credentials grant requests
func (f *ClientCredentialsFlow) Handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔧 Processing client credentials request")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, "invalid_request", "Failed to parse request")
		return
	}

	grantType := r.FormValue("grant_type")
	scope := r.FormValue("scope")

	if grantType != "client_credentials" {
		utils.WriteErrorResponse(w, "unsupported_grant_type", "Grant type must be client_credentials")
		return
	}

	// Extract client credentials
	clientID, clientSecret, err := auth.ExtractClientCredentials(r)
	if err != nil {
		utils.WriteInvalidClientError(w, "Client authentication required")
		return
	}

	// Authenticate client
	ctx := context.Background()
	client, err := f.clientStore.GetClient(ctx, clientID)
	if err != nil {
		log.Printf("❌ Client not found: %s", clientID)
		utils.WriteErrorResponse(w, "invalid_client", "Client not found")
		return
	}

	// Validate client credentials
	if err := f.clientStore.ValidateClientCredentials(clientID, clientSecret); err != nil {
		log.Printf("❌ Client authentication failed for %s: %v", clientID, err)
		utils.WriteErrorResponse(w, "invalid_client", "Client authentication failed")
		return
	}

	// Check if client is authorized for client_credentials grant
	if !auth.ClientHasGrantType(client, "client_credentials") {
		utils.WriteErrorResponse(w, "unauthorized_client", "Client not authorized for client_credentials grant")
		return
	}

	// Validate requested scopes
	if scope != "" && !auth.ClientHasScope(client, scope) {
		utils.WriteErrorResponse(w, "invalid_scope", "Requested scope not authorized for client")
		return
	}

	// Use client's default scopes if none requested
	if scope == "" {
		scope = "api:read api:write" // Default scopes for client credentials
	}

	// Parse and validate scopes
	requestedScopes := utils.SplitScopes(scope)
	if len(requestedScopes) == 0 {
		requestedScopes = []string{"openid"} // Default scope
	}

	// Validate requested scopes against client's allowed scopes
	allowedScopes := client.GetScopes()
	if len(allowedScopes) > 0 {
		requestedScopes = utils.FilterScopes(requestedScopes, allowedScopes)
		if len(requestedScopes) == 0 {
			utils.WriteErrorResponse(w, "invalid_scope", "No valid scopes found")
			return
		}
	}

	// Generate access token using high-level function (and store it)
	expiresIn := time.Hour
	accessToken, err := auth.GenerateAccessToken(f.tokenStore, "", clientID, requestedScopes, expiresIn)
	if err != nil {
		log.Printf("❌ Error generating access token: %v", err)
		utils.WriteServerError(w, "Failed to generate access token")
		return
	}

	// Create response
	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600, // 1 hour
		"scope":        utils.JoinScopes(requestedScopes),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Access token issued for client: %s", clientID)
}
