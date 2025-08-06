package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/config"
	"oauth2-server/internal/storage"
	"strings"
	"time"
)

// ClientRegistrationRequest represents a dynamic client registration request (RFC 7591)
type ClientRegistrationRequest struct {
	RedirectURIs            []string    `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string    `json:"grant_types,omitempty"`
	ResponseTypes           []string    `json:"response_types,omitempty"`
	ClientName              string      `json:"client_name,omitempty"`
	ClientURI               string      `json:"client_uri,omitempty"`
	LogoURI                 string      `json:"logo_uri,omitempty"`
	Scope                   string      `json:"scope,omitempty"`
	Contacts                []string    `json:"contacts,omitempty"`
	TosURI                  string      `json:"tos_uri,omitempty"`
	PolicyURI               string      `json:"policy_uri,omitempty"`
	JwksURI                 string      `json:"jwks_uri,omitempty"`
	Jwks                    interface{} `json:"jwks,omitempty"`
	SoftwareID              string      `json:"software_id,omitempty"`
	SoftwareVersion         string      `json:"software_version,omitempty"`

	// Additional fields that match your ClientConfig
	Description        string   `json:"description,omitempty"`
	AllowTokenExchange bool     `json:"allow_token_exchange,omitempty"`
	AllowedAudiences   []string `json:"allowed_audiences,omitempty"`
	AllowedOrigins     []string `json:"allowed_origins,omitempty"`
}

// ClientRegistrationResponse represents a dynamic client registration response (RFC 7591)
type ClientRegistrationResponse struct {
	ClientID                string      `json:"client_id"`
	ClientSecret            string      `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64       `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64       `json:"client_secret_expires_at"`
	RedirectURIs            []string    `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string    `json:"grant_types,omitempty"`
	ResponseTypes           []string    `json:"response_types,omitempty"`
	ClientName              string      `json:"client_name,omitempty"`
	ClientURI               string      `json:"client_uri,omitempty"`
	LogoURI                 string      `json:"logo_uri,omitempty"`
	Scope                   string      `json:"scope,omitempty"`
	Contacts                []string    `json:"contacts,omitempty"`
	TosURI                  string      `json:"tos_uri,omitempty"`
	PolicyURI               string      `json:"policy_uri,omitempty"`
	JwksURI                 string      `json:"jwks_uri,omitempty"`
	Jwks                    interface{} `json:"jwks,omitempty"`
	SoftwareID              string      `json:"software_id,omitempty"`
	SoftwareVersion         string      `json:"software_version,omitempty"`
	RegistrationAccessToken string      `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string      `json:"registration_client_uri,omitempty"`

	// Additional fields that match your ClientConfig
	Description        string   `json:"description,omitempty"`
	AllowTokenExchange bool     `json:"allow_token_exchange,omitempty"`
	AllowedAudiences   []string `json:"allowed_audiences,omitempty"`
	AllowedOrigins     []string `json:"allowed_origins,omitempty"`
}

// HandleClientRegistration handles dynamic client registration (RFC 7591)
func (h *Handlers) HandleClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid_request", "Invalid JSON", http.StatusBadRequest)
		return
	}

	clientID := "client_" + generateRandomString(16)
	clientSecret := generateRandomString(32)

	// Set defaults for required fields
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	// Create ClientConfig that matches your struct exactly
	clientConfig := &config.ClientConfig{
		ID:                      clientID,
		Secret:                  clientSecret,
		Name:                    req.ClientName,
		Description:             req.Description,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scopes:                  strings.Fields(req.Scope),
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Public:                  req.TokenEndpointAuthMethod == "none",
		AllowTokenExchange:      req.AllowTokenExchange,
		AllowedAudiences:        req.AllowedAudiences,
		AllowedOrigins:          req.AllowedOrigins,
	}

	// Convert config.ClientConfig to storage.DynamicClient
	dynamicClient := &storage.DynamicClient{
		ClientID:                clientConfig.ID,
		ClientSecret:            clientConfig.Secret,
		ClientName:              clientConfig.Name,
		Description:             clientConfig.Description,
		RedirectURIs:            clientConfig.RedirectURIs,
		GrantTypes:              clientConfig.GrantTypes,
		ResponseTypes:           clientConfig.ResponseTypes,
		Scopes:                  clientConfig.Scopes,
		TokenEndpointAuthMethod: clientConfig.TokenEndpointAuthMethod,
		Public:                  clientConfig.Public,
		AllowedAudiences:        clientConfig.AllowedAudiences,
		AllowTokenExchange:      clientConfig.AllowTokenExchange,
		AllowedOrigins:          clientConfig.AllowedOrigins,
		ClientIDIssuedAt:        time.Now(),
		ClientSecretExpiresAt:   time.Time{}, // Set to zero time if no expiry
		CreatedAt:               time.Now(),
		UpdatedAt:               time.Now(),
	}

	// Store using the new interface signature
	if err := h.Storage.StoreDynamicClient(dynamicClient); err != nil {
		h.Logger.WithError(err).Error("Failed to store client")
		h.writeError(w, "server_error", "Failed to register client", http.StatusInternalServerError)
		return
	}

	response := ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0, // 0 means never expires
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TosURI:                  req.TosURI,
		PolicyURI:               req.PolicyURI,
		JwksURI:                 req.JwksURI,
		Jwks:                    req.Jwks,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		Description:             req.Description,
		AllowTokenExchange:      req.AllowTokenExchange,
		AllowedAudiences:        req.AllowedAudiences,
		AllowedOrigins:          req.AllowedOrigins,
	}

	h.Logger.Debugf("Dynamic client registration successful: client_id=%s, name=%s", clientID, req.ClientName)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}
