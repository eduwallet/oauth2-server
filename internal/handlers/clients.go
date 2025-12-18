package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"strings"
	"time"
)

// ClientMetadata represents the client registration request
type ClientMetadata struct {
	ClientID                string                          `json:"client_id,omitempty"`
	ClientSecret            string                          `json:"client_secret,omitempty"`
	RedirectURIs            []string                        `json:"redirect_uris"`
	TokenEndpointAuthMethod string                          `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string                        `json:"grant_types,omitempty"`
	ResponseTypes           []string                        `json:"response_types,omitempty"`
	ClientName              string                          `json:"client_name,omitempty"`
	ClientURI               string                          `json:"client_uri,omitempty"`
	LogoURI                 string                          `json:"logo_uri,omitempty"`
	Scope                   string                          `json:"scope,omitempty"`
	Claims                  string                          `json:"claims,omitempty"`
	Contacts                []string                        `json:"contacts,omitempty"`
	TermsOfServiceURI       string                          `json:"tos_uri,omitempty"`
	PolicyURI               string                          `json:"policy_uri,omitempty"`
	JwksURI                 string                          `json:"jwks_uri,omitempty"`
	Jwks                    string                          `json:"jwks,omitempty"`
	SoftwareID              string                          `json:"software_id,omitempty"`
	SoftwareVersion         string                          `json:"software_version,omitempty"`
	ForceAuthentication     bool                            `json:"force_authentication,omitempty"`
	ForceConsent            bool                            `json:"force_consent,omitempty"`
	Audience                []string                        `json:"audience,omitempty"`
	AttestationConfig       *config.ClientAttestationConfig `json:"attestation_config,omitempty"`
	Public                  bool                            `json:"public,omitempty"`
}

// ClientResponse represents the client registration response
type ClientResponse struct {
	ClientID                string                          `json:"client_id"`
	ClientSecret            string                          `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64                           `json:"client_secret_expires_at"`
	RegistrationAccessToken string                          `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string                          `json:"registration_client_uri,omitempty"`
	ClientIdIssuedAt        int64                           `json:"client_id_issued_at"`
	RedirectURIs            []string                        `json:"redirect_uris"`
	TokenEndpointAuthMethod string                          `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string                        `json:"grant_types,omitempty"`
	ResponseTypes           []string                        `json:"response_types,omitempty"`
	ClientName              string                          `json:"client_name,omitempty"`
	ClientURI               string                          `json:"client_uri,omitempty"`
	LogoURI                 string                          `json:"logo_uri,omitempty"`
	Scope                   string                          `json:"scope,omitempty"`
	Claims                  string                          `json:"claims,omitempty"`
	Contacts                []string                        `json:"contacts,omitempty"`
	TermsOfServiceURI       string                          `json:"tos_uri,omitempty"`
	PolicyURI               string                          `json:"policy_uri,omitempty"`
	JwksURI                 string                          `json:"jwks_uri,omitempty"`
	Jwks                    string                          `json:"jwks,omitempty"`
	SoftwareID              string                          `json:"software_id,omitempty"`
	SoftwareVersion         string                          `json:"software_version,omitempty"`
	ForceAuthentication     bool                            `json:"force_authentication,omitempty"`
	ForceConsent            bool                            `json:"force_consent,omitempty"`
	Audience                []string                        `json:"audience,omitempty"`
	AttestationConfig       *config.ClientAttestationConfig `json:"attestation_config,omitempty"`
	Public                  bool                            `json:"public,omitempty"`
}

// HandleClients handles client management requests (GET and DELETE)
func (h *RegistrationHandler) HandleClients(w http.ResponseWriter, r *http.Request) {
	// Parse the path to extract client ID if present
	remaining := strings.TrimPrefix(r.URL.Path, "/clients")
	var clientID string
	if remaining == "" || remaining == "/" {
		clientID = ""
	} else if strings.HasPrefix(remaining, "/") {
		clientID = strings.TrimPrefix(remaining, "/")
		h.log.Printf("🔍 [CLIENTS] Client ID from path: %s", clientID)
	} else {
		// This shouldn't happen with proper routing, but handle gracefully
		clientID = remaining
		h.log.Printf("🔍 [CLIENTS] Unexpected path format, client ID: %s", clientID)
	}

	// Handle different methods
	switch r.Method {
	case "GET":
		h.handleGetClients(w, r, clientID)
	case "DELETE":
		h.handleDeleteClient(w, r, clientID)
	default:
		h.log.Errorf("❌ [CLIENTS] Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// handleGetClients handles GET requests for listing or retrieving clients
func (h *RegistrationHandler) handleGetClients(w http.ResponseWriter, r *http.Request, clientID string) {
	w.Header().Set("Content-Type", "application/json")

	if clientID == "" {
		// GET /clients - list all client IDs
		h.log.Printf("🔍 [CLIENTS] Listing all registered clients")

		// Get all clients from storage
		clients, err := h.storage.ListClients(r.Context())
		if err != nil {
			h.log.Errorf("❌ [CLIENTS] Failed to list clients: %v", err)
			http.Error(w, "Failed to list clients", http.StatusInternalServerError)
			return
		}

		// Extract client IDs
		clientIDs := make([]string, 0, len(clients))
		for _, client := range clients {
			if client != nil && client.GetID() != "" {
				clientIDs = append(clientIDs, client.GetID())
			}
		}

		h.log.Printf("✅ [CLIENTS] Found %d registered clients", len(clientIDs))

		response := map[string]interface{}{
			"client_ids": clientIDs,
			"count":      len(clientIDs),
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			h.log.Errorf("❌ [CLIENTS] Failed to encode response: %v", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	} else {
		// GET /clients/<client-id> - get client details
		h.log.Printf("🔍 [CLIENTS] Retrieving details for client: %s", clientID)

		client, err := h.storage.GetClient(r.Context(), clientID)
		if err != nil {
			h.log.Errorf("❌ [CLIENTS] Client not found: %s", clientID)
			http.Error(w, "Client not found", http.StatusNotFound)
			return
		}

		// Get client secret if available
		var clientSecret string
		if !client.IsPublic() {
			if secret, ok := GetClientSecret(r.Context(), clientID, h.storage, h.secretManager); ok {
				clientSecret = secret
			}
		}

		// Get attestation config if available
		var attestationConfig *config.ClientAttestationConfig
		if config, ok := GetClientAttestationConfig(r.Context(), clientID, h.storage); ok {
			attestationConfig = config
		}

		// Get claims if client supports it
		var (
			claims              string
			forceAuthentication bool
			forceConsent        bool
		)
		if customClient, ok := client.(*store.CustomClient); ok {
			if customClient.Claims != nil {
				claims = strings.Join(customClient.Claims, " ")
			}
			forceAuthentication = customClient.ForceAuthentication
			forceConsent = customClient.ForceConsent
		}

		// Build response similar to registration response
		now := time.Now().Unix()
		response := ClientResponse{
			ClientID:                client.GetID(),
			ClientSecret:            clientSecret,
			ClientSecretExpiresAt:   0, // 0 means no expiration
			ClientIdIssuedAt:        now,
			RegistrationAccessToken: "", // Not implemented
			RegistrationClientURI:   "", // Not implemented
			RedirectURIs:            client.GetRedirectURIs(),
			TokenEndpointAuthMethod: "client_secret_basic", // Default, since not stored
			GrantTypes:              client.GetGrantTypes(),
			ResponseTypes:           client.GetResponseTypes(),
			ClientName:              "", // Not stored
			ClientURI:               "", // Not stored
			LogoURI:                 "", // Not stored
			Scope:                   strings.Join(client.GetScopes(), " "),
			Claims:                  claims,
			Contacts:                []string{}, // Not stored
			TermsOfServiceURI:       "",         // Not stored
			PolicyURI:               "",         // Not stored
			JwksURI:                 "",         // Not stored
			Jwks:                    "",         // Not stored
			SoftwareID:              "",         // Not stored
			SoftwareVersion:         "",         // Not stored
			ForceAuthentication:     forceAuthentication,
			ForceConsent:            forceConsent,
			Audience:                client.GetAudience(),
			AttestationConfig:       attestationConfig,
			Public:                  client.IsPublic(),
		}

		h.log.Printf("✅ [CLIENTS] Retrieved details for client: %s", clientID)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			h.log.Errorf("❌ [CLIENTS] Failed to encode response: %v", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}
}

// handleDeleteClient handles DELETE requests for removing clients
func (h *RegistrationHandler) handleDeleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	if clientID == "" {
		h.log.Errorf("❌ [CLIENTS] Client ID required for deletion")
		http.Error(w, "Client ID required", http.StatusBadRequest)
		return
	}

	h.log.Printf("🔍 [CLIENTS] Deleting client: %s", clientID)

	// Check if client exists
	_, err := h.storage.GetClient(r.Context(), clientID)
	if err != nil {
		h.log.Errorf("❌ [CLIENTS] Client not found: %s", clientID)
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	// Delete the client
	if err := h.storage.DeleteClient(r.Context(), clientID); err != nil {
		h.log.Errorf("❌ [CLIENTS] Failed to delete client: %v", err)
		http.Error(w, "Failed to delete client", http.StatusInternalServerError)
		return
	}

	// Also delete client secret and attestation config if they exist
	if err := h.storage.DeleteClientSecret(r.Context(), clientID); err != nil {
		h.log.Warnf("⚠️ [CLIENTS] Failed to delete client secret for %s: %v", clientID, err)
	}

	if err := h.storage.DeleteAttestationConfig(r.Context(), clientID); err != nil {
		h.log.Warnf("⚠️ [CLIENTS] Failed to delete attestation config for %s: %v", clientID, err)
	}

	h.log.Printf("✅ [CLIENTS] Successfully deleted client: %s", clientID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"message":   "Client deleted successfully",
		"client_id": clientID,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Errorf("❌ [CLIENTS] Failed to encode response: %v", err)
		// Headers already written, can't send error
		return
	}
}
