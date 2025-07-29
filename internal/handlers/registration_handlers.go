package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"oauth2-server/internal/models"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// RegistrationHandlers handles dynamic client registration
type RegistrationHandlers struct {
	clientStore *store.ClientStore
	config      *config.Config
}

// NewRegistrationHandlers creates a new registration handlers instance
func NewRegistrationHandlers(clientStore *store.ClientStore, config *config.Config) *RegistrationHandlers {
	return &RegistrationHandlers{
		clientStore: clientStore,
		config:      config,
	}
}

// HandleRegistration handles client registration requests (POST /register)
func (h *RegistrationHandlers) HandleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		utils.WriteMethodNotAllowedError(w)
		return
	}

	var req models.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteInvalidRequestError(w, "JSON decoding error")
		return
	}

	// Generate client credentials
	clientID, err := h.generateClientID()
	if err != nil {
		utils.WriteServerError(w, "Failed to generate client ID")
		return
	}

	clientSecret, err := h.generateClientSecret()
	if err != nil {
		utils.WriteServerError(w, "Failed to generate client secret")
		return
	}

	// Set default grant types if not provided
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	// Validate required fields
	if len(req.RedirectURIs) == 0 {
		if utils.Contains(grantTypes, "authorization_code") || utils.Contains(grantTypes, "implicit") {
			utils.WriteInvalidRequestError(w, "At least one redirect URI is required")
			return
		}
	}

	// Convert scope string to slice
	var scopes []string
	if req.Scope != "" {
		scopes = strings.Fields(req.Scope)
	} else {
		scopes = []string{"openid", "profile", "email"}
	}

	// Set default response types if not provided
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		if utils.Contains(grantTypes, "authorization_code") {
			responseTypes = []string{"code"}
		}
		if utils.Contains(grantTypes, "implicit") {
			responseTypes = append(responseTypes, "token")
		}
	}

	// Set default token endpoint auth method
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}

	// Generate registration access token
	registrationAccessToken, err := h.generateRegistrationAccessToken()
	if err != nil {
		utils.WriteServerError(w, "Failed to generate registration access token")
		return
	}

	// Create client info
	clientInfo := models.ClientInfo{
		ID:            clientID,
		Secret:        clientSecret,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: responseTypes,
		Scopes:        scopes,
		ClientName:    req.ClientName,
		ClientURI:     req.ClientURI,
		LogoURI:       req.LogoURI,
		ContactEmails: req.Contacts,
		Audience:      req.Audience, // <-- Add this line
	}

	// Store the client
	client := store.CreateDefaultClient(clientInfo)
	if err := h.clientStore.StoreClient(client); err != nil {
		log.Printf("❌ Failed to store client: %v", err)
		utils.WriteServerError(w, "Failed to register client")
		return
	}

	// Create response
	response := models.ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientSecretExpiresAt:   time.Now().Add(365 * 24 * time.Hour).Unix(),
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scope:                   strings.Join(scopes, " "),
		Contacts:                req.Contacts,
		Audience:                req.Audience, // <-- Add this line
		TosURI:                  req.TosURI,
		PolicyURI:               req.PolicyURI,
		TokenEndpointAuthMethod: authMethod,
		ApplicationType:         req.ApplicationType,
		RegistrationAccessToken: registrationAccessToken,
		RegistrationClientURI:   fmt.Sprintf("%s/register/%s", h.config.BaseURL, clientID),
		CreatedAt:               time.Now(),
		UpdatedAt:               time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Client registered: %s (%s)", clientID, req.ClientName)
}

// HandleClientConfiguration handles client configuration requests (GET/PUT/DELETE /register/{client_id})
func (h *RegistrationHandlers) HandleClientConfiguration(w http.ResponseWriter, r *http.Request) {
	// Extract client ID from path
	clientID := h.extractClientIDFromPath(r.URL.Path)
	if clientID == "" {
		utils.WriteInvalidRequestError(w, "Missing client ID")
		return
	}

	// Validate registration access token for all operations
	if !h.validateRegistrationAccessToken(r, clientID) {
		utils.WriteInvalidRequestError(w, "Invalid registration access token")
		return
	}

	switch r.Method {
	case "GET":
		h.getClient(w, r, clientID)
	case "PUT":
		h.updateClient(w, r, clientID)
	case "DELETE":
		h.deleteClient(w, r, clientID)
	default:
		utils.WriteMethodNotAllowedError(w)
	}
}

// getClient retrieves client information
func (h *RegistrationHandlers) getClient(w http.ResponseWriter, r *http.Request, clientID string) {
	ctx := context.Background()
	client, err := h.clientStore.GetClient(ctx, clientID)
	if err != nil {
		utils.WriteJSONError(w)
		return
	}

	// Convert to registration response format
	response := models.ClientRegistrationResponse{
		ClientID:              client.GetID(),
		ClientName:            "OAuth2 Client",
		RedirectURIs:          client.GetRedirectURIs(),
		GrantTypes:            client.GetGrantTypes(),
		ResponseTypes:         client.GetResponseTypes(),
		Scope:                 strings.Join(client.GetScopes(), " "),
		RegistrationClientURI: fmt.Sprintf("%s/register/%s", h.config.BaseURL, clientID),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateClient updates client information
func (h *RegistrationHandlers) updateClient(w http.ResponseWriter, r *http.Request, clientID string) {
	var req models.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSONError(w)
		return
	}

	// Get existing client to ensure it exists
	ctx := context.Background()
	_, err := h.clientStore.GetClient(ctx, clientID)
	if err != nil {
		utils.WriteClientNotFoundError(w, clientID)
		return
	}

	response := models.ClientRegistrationResponse{
		ClientID:              clientID,
		ClientName:            req.ClientName,
		RedirectURIs:          req.RedirectURIs,
		GrantTypes:            req.GrantTypes,
		ResponseTypes:         req.ResponseTypes,
		Scope:                 req.Scope,
		UpdatedAt:             time.Now(),
		RegistrationClientURI: fmt.Sprintf("%s/register/%s", h.config.BaseURL, clientID),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Client updated: %s", clientID)
}

// deleteClient deletes a client
func (h *RegistrationHandlers) deleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	if err := h.clientStore.DeleteClient(clientID); err != nil {
		utils.WriteClientNotFoundError(w, clientID)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	log.Printf("✅ Client deleted: %s", clientID)
}

// Helper methods
func (h *RegistrationHandlers) generateClientID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "client_" + hex.EncodeToString(bytes), nil
}

func (h *RegistrationHandlers) generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "secret_" + hex.EncodeToString(bytes), nil
}

func (h *RegistrationHandlers) generateRegistrationAccessToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "reg_" + hex.EncodeToString(bytes), nil
}

func (h *RegistrationHandlers) extractClientIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func (h *RegistrationHandlers) validateRegistrationAccessToken(r *http.Request, clientID string) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	return strings.HasPrefix(token, "reg_")
}
