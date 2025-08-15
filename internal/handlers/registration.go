package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"oauth2-server/internal/utils"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// RegistrationHandler manages dynamic client registration

type RegistrationHandler struct {
	memoryStore *storage.MemoryStore
}

// NewRegistrationHandler creates a new registration handler
func NewRegistrationHandler(memoryStore *storage.MemoryStore) *RegistrationHandler {
	return &RegistrationHandler{
		memoryStore: memoryStore,
	}
}

// ClientMetadata represents the client registration request
type ClientMetadata struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TermsOfServiceURI       string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	Jwks                    string   `json:"jwks,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	Audience                []string `json:"audience,omitempty"`
}

// ClientResponse represents the client registration response
type ClientResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	ClientIdIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TermsOfServiceURI       string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	Jwks                    string   `json:"jwks,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	Audience                []string `json:"audience,omitempty"`
}

// HandleRegistration handles client registration requests
func (h *RegistrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var metadata ClientMetadata
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate client ID (random string)
	clientID, err := generateRandomString(32)
	if err != nil {
		http.Error(w, "Failed to generate client ID", http.StatusInternalServerError)
		return
	}

	// Generate client secret
	clientSecret, err := generateRandomString(64)
	if err != nil {
		http.Error(w, "Failed to generate client secret", http.StatusInternalServerError)
		return
	}

	// Hash the client secret
	hashedSecret, err := utils.HashSecret(clientSecret)
	if err != nil {
		http.Error(w, "Failed to hash client secret", http.StatusInternalServerError)
		return
	}

	// Apply defaults if needed
	grantTypes := metadata.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	responseTypes := metadata.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	// Debug: Log the registration details
	log.Printf("🔍 Registering client with Grant Types: %v, Response Types: %v", grantTypes, responseTypes)

	// Convert scope string to array if provided
	var scopes []string
	if metadata.Scope != "" {
		scopes = splitScope(metadata.Scope)
	}

	// Convert audience string to array if provided
	var audience []string
	if len(metadata.Audience) != 0 {
		audience = metadata.Audience
	}

	// Always add the client ID to its own audience whitelist
	if clientID != "" && !contains(audience, clientID) {
		audience = append(audience, clientID)
	}

	// Debug: Log scope information
	log.Printf("🔍 Client scopes from metadata: '%s' -> %v", metadata.Scope, scopes)
	log.Printf("🔍 Client audience from metadata: '%s' -> %v", metadata.Audience, audience)

	// Create the client
	newClient := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  metadata.RedirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: responseTypes,
		Scopes:        scopes,
		Audience:      audience,
		Public:        metadata.TokenEndpointAuthMethod == "none",
	}

	// Store the client
	h.memoryStore.Clients[clientID] = newClient

	// Prepare the response
	now := time.Now().Unix()
	response := ClientResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret, // Return unhashed secret to client
		ClientSecretExpiresAt:   0,            // 0 means no expiration
		ClientIdIssuedAt:        now,
		RegistrationAccessToken: "", // Not implemented in this example
		RegistrationClientURI:   "", // Not implemented in this example
		RedirectURIs:            metadata.RedirectURIs,
		TokenEndpointAuthMethod: metadata.TokenEndpointAuthMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		ClientName:              metadata.ClientName,
		ClientURI:               metadata.ClientURI,
		LogoURI:                 metadata.LogoURI,
		Scope:                   strings.Join(scopes, " "),
		Contacts:                metadata.Contacts,
		TermsOfServiceURI:       metadata.TermsOfServiceURI,
		PolicyURI:               metadata.PolicyURI,
		JwksURI:                 metadata.JwksURI,
		Jwks:                    metadata.Jwks,
		SoftwareID:              metadata.SoftwareID,
		SoftwareVersion:         metadata.SoftwareVersion,
		Audience:                audience,
	}

	log.Printf("✅ Registered new client: %s", clientID)

	// Return the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Helper function to generate a random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// Helper function to split a scope string into an array
func splitScope(scope string) []string {
	// In a real implementation, you would use a proper tokenizer
	// that handles quoted strings, etc.
	return strings.Fields(scope)
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
