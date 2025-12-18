package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2-server/internal/attestation"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
	"strings"
	"time"

	"context"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// RegistrationHandler manages dynamic client registration
type RegistrationHandler struct {
	storage            *store.CustomStorage
	secretManager      *store.SecretManager
	trustAnchorHandler *TrustAnchorHandler
	attestationManager *attestation.VerifierManager
	config             *config.Config
	log                *logrus.Logger
}

// NewRegistrationHandler creates a new registration handler
func NewRegistrationHandler(storage *store.CustomStorage, secretManager *store.SecretManager, trustAnchorHandler *TrustAnchorHandler, attestationManager *attestation.VerifierManager, config *config.Config, log *logrus.Logger) *RegistrationHandler {
	return &RegistrationHandler{
		storage:            storage,
		secretManager:      secretManager,
		trustAnchorHandler: trustAnchorHandler,
		attestationManager: attestationManager,
		config:             config,
		log:                log,
	}
}

// HandleRegistration handles client registration requests (POST only)
func (h *RegistrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		h.log.Errorf("❌ [REGISTRATION] Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.log.Printf("✅ [REGISTRATION] Method is POST, proceeding to parse request body")

	// Parse request body
	var metadata ClientMetadata
	h.log.Printf("🔍 [REGISTRATION] Attempting to decode JSON request body")
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		h.log.Errorf("❌ [REGISTRATION] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.log.Printf("✅ [REGISTRATION] Successfully decoded request body")
	h.log.Printf("🔍 [REGISTRATION] ClientID: '%s'", metadata.ClientID)
	h.log.Printf("🔍 [REGISTRATION] TokenEndpointAuthMethod: '%s'", metadata.TokenEndpointAuthMethod)
	h.log.Printf("🔍 [REGISTRATION] GrantTypes: %v", metadata.GrantTypes)
	h.log.Printf("🔍 [REGISTRATION] ResponseTypes: %v", metadata.ResponseTypes)
	h.log.Printf("🔍 [REGISTRATION] RedirectURIs: %v", metadata.RedirectURIs)
	h.log.Printf("🔍 [REGISTRATION] Scope: '%s'", metadata.Scope)
	h.log.Printf("🔍 [REGISTRATION] AttestationConfig present: %v", metadata.AttestationConfig != nil)

	var clientID string
	var isUpdate bool

	// Check if client_id is provided
	if metadata.ClientID != "" {
		clientID = metadata.ClientID
		h.log.Printf("🔍 [REGISTRATION] Client ID provided: %s", clientID)
		// Check if client already exists
		if _, err := h.storage.GetClient(r.Context(), clientID); err == nil {
			isUpdate = true
			h.log.Printf("🔄 [REGISTRATION] Updating existing client: %s", clientID)
		} else {
			h.log.Printf("📝 [REGISTRATION] Creating new client with provided ID: %s", clientID)
		}
	} else {
		h.log.Printf("🔍 [REGISTRATION] No client ID provided, generating new one")
		// Generate client ID (random string)
		var err error
		clientID, err = generateRandomString(32)
		if err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to generate client ID: %v", err)
			http.Error(w, "Failed to generate client ID", http.StatusInternalServerError)
			return
		}
		h.log.Printf("🆕 [REGISTRATION] Generated new client ID: %s", clientID)
	}

	h.log.Printf("✅ [REGISTRATION] Client ID determined: %s (isUpdate: %v)", clientID, isUpdate)

	// Determine if client is public
	// Check if explicitly set in request, otherwise infer from auth method
	isPublic := metadata.Public
	if !metadata.Public {
		// If not explicitly set, infer from auth method
		isPublic = (metadata.TokenEndpointAuthMethod == "none")
	}
	h.log.Printf("🔍 [REGISTRATION] Client is public: %v (explicit: %v, auth_method: %s, has_attestation: %v)", isPublic, metadata.Public, metadata.TokenEndpointAuthMethod, metadata.AttestationConfig != nil)

	// Generate client secret only for new clients and non-public clients
	var clientSecret string
	var hashedSecret []byte
	var err error

	if !isUpdate && !isPublic {
		if metadata.ClientSecret != "" {
			h.log.Printf("🔍 [REGISTRATION] Using provided client secret")
			clientSecret = metadata.ClientSecret
		} else {
			h.log.Printf("🔍 [REGISTRATION] Generating client secret for new confidential client")
			clientSecret, err = generateRandomString(64)
			if err != nil {
				h.log.Errorf("❌ [REGISTRATION] Failed to generate client secret: %v", err)
				http.Error(w, "Failed to generate client secret", http.StatusInternalServerError)
				return
			}
			h.log.Printf("✅ [REGISTRATION] Generated client secret (length: %d)", len(clientSecret))
		}

		// Hash the client secret
		h.log.Printf("🔍 [REGISTRATION] Hashing client secret")
		hashedSecret, err = utils.HashSecret(clientSecret)
		if err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to hash client secret: %v", err)
			http.Error(w, "Failed to hash client secret", http.StatusInternalServerError)
			return
		}
		h.log.Printf("✅ [REGISTRATION] Client secret hashed successfully")
	} else if isUpdate && !isPublic {
		h.log.Printf("🔍 [REGISTRATION] Update operation - retrieving existing client secret")
		// For updates, keep the existing secret
		if existingClient, err := h.storage.GetClient(r.Context(), clientID); err == nil {
			if defaultClient, ok := existingClient.(*fosite.DefaultClient); ok {
				hashedSecret = defaultClient.Secret
				h.log.Printf("✅ [REGISTRATION] Retrieved existing hashed secret")
			} else {
				h.log.Errorf("❌ [REGISTRATION] Failed to cast existing client to DefaultClient")
				http.Error(w, "Failed to access existing client secret", http.StatusInternalServerError)
				return
			}
		} else {
			h.log.Errorf("❌ [REGISTRATION] Existing client not found in storage: %v", err)
			http.Error(w, "Client not found", http.StatusNotFound)
			return
		}
	} else {
		h.log.Printf("🔍 [REGISTRATION] Public client - no secret needed")
		hashedSecret = nil
	}

	h.log.Printf("✅ [REGISTRATION] Client secret handling completed") // Handle attestation config for updates
	var finalAttestationConfig *config.ClientAttestationConfig
	if metadata.AttestationConfig != nil {
		h.log.Printf("🔍 [REGISTRATION] Attestation config provided in request")
		finalAttestationConfig = metadata.AttestationConfig
	} else if isUpdate {
		h.log.Printf("⚠️  [REGISTRATION] Update without attestation config - existing config will be lost")
		// For updates without new attestation config, we can't preserve existing config
		// since fosite.DefaultClient doesn't store it. This is a limitation.
		// In a full implementation, we'd need to store attestation config separately.
		h.log.Printf("⚠️  [REGISTRATION] Updating client without attestation config - existing attestation config will be lost")
	}

	h.log.Printf("✅ [REGISTRATION] Attestation config handling completed")

	// Apply defaults if needed
	grantTypes := metadata.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
		h.log.Printf("🔍 [REGISTRATION] Applied default grant types: %v", grantTypes)
	}

	responseTypes := metadata.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
		h.log.Printf("🔍 [REGISTRATION] Applied default response types: %v", responseTypes)
	}

	h.log.Printf("✅ [REGISTRATION] Grant types: %v, Response types: %v", grantTypes, responseTypes)

	// Validate attestation configuration if using attestation auth
	authMethod := metadata.TokenEndpointAuthMethod
	h.log.Printf("🔍 [REGISTRATION] Checking attestation validation for auth method: '%s'", authMethod)
	if authMethod == "attest_jwt_client_auth" || authMethod == "attest_tls_client_auth" {
		h.log.Printf("🔍 [REGISTRATION] Attestation-based auth method detected, validating config")
		if metadata.AttestationConfig == nil {
			h.log.Errorf("❌ [REGISTRATION] Attestation config required but not provided")
			http.Error(w, "Attestation configuration required for attestation-based authentication", http.StatusBadRequest)
			return
		}
		h.log.Printf("🔍 [REGISTRATION] Validating attestation configuration")
		if err := metadata.AttestationConfig.Validate(); err != nil {
			h.log.Errorf("❌ [REGISTRATION] Invalid attestation configuration: %v", err)
			http.Error(w, "Invalid attestation configuration: "+err.Error(), http.StatusBadRequest)
			return
		}
		h.log.Printf("✅ [REGISTRATION] Attestation configuration validated")

		// Ensure the attestation config client_id matches the client being registered
		if metadata.AttestationConfig.ClientID != "" && metadata.AttestationConfig.ClientID != clientID {
			h.log.Errorf("❌ [REGISTRATION] Attestation config client_id mismatch: config=%s, client=%s", metadata.AttestationConfig.ClientID, clientID)
			http.Error(w, "Attestation config client_id must match the registered client_id", http.StatusBadRequest)
			return
		}
		// Set the client_id in attestation config if not provided
		if metadata.AttestationConfig.ClientID == "" {
			metadata.AttestationConfig.ClientID = clientID
			h.log.Printf("🔍 [REGISTRATION] Set attestation config client_id to: %s", clientID)
		}

		// Resolve trust anchor names to file paths
		h.log.Printf("🔍 [REGISTRATION] Resolving trust anchors: %v", metadata.AttestationConfig.TrustAnchors)
		if err := h.resolveTrustAnchors(r.Context(), metadata.AttestationConfig); err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to resolve trust anchors: %v", err)
			http.Error(w, "Failed to resolve trust anchors: "+err.Error(), http.StatusBadRequest)
			return
		}
		h.log.Printf("✅ [REGISTRATION] Trust anchors resolved: %v", metadata.AttestationConfig.TrustAnchors)

		finalAttestationConfig = metadata.AttestationConfig

		// Ensure client_credentials grant type is included for attestation clients
		hasClientCredentials := false
		for _, gt := range grantTypes {
			if gt == "client_credentials" {
				hasClientCredentials = true
				break
			}
		}
		if !hasClientCredentials {
			grantTypes = append(grantTypes, "client_credentials")
			h.log.Printf("✅ [REGISTRATION] Added client_credentials grant type for attestation client")
		}
	} else {
		h.log.Printf("🔍 [REGISTRATION] No attestation validation required for auth method: '%s'", authMethod)
	}

	// Debug: Log the registration details
	h.log.Printf("🔍 [REGISTRATION] Final registration details - Grant Types: %v, Response Types: %v", grantTypes, responseTypes)

	// Convert scope string to array if provided
	var scopes []string
	if metadata.Scope != "" {
		scopes = splitScope(metadata.Scope)
		h.log.Printf("🔍 [REGISTRATION] Split scope string '%s' into: %v", metadata.Scope, scopes)
	} else {
		h.log.Printf("🔍 [REGISTRATION] No scope provided")
	}

	// Always include "openid" scope
	if !contains(scopes, "openid") {
		scopes = append(scopes, "openid")
		h.log.Printf("🔍 [REGISTRATION] Added 'openid' to scopes: %v", scopes)
	}

	// Convert audience string to array if provided
	var audience []string
	if len(metadata.Audience) != 0 {
		audience = metadata.Audience
		h.log.Printf("🔍 [REGISTRATION] Using provided audience: %v", audience)
	} else {
		h.log.Printf("🔍 [REGISTRATION] No audience provided")
	}

	// Always add the client ID to its own audience whitelist
	if clientID != "" && !contains(audience, clientID) {
		audience = append(audience, clientID)
		h.log.Printf("🔍 [REGISTRATION] Added client ID to audience: %v", audience)
	}

	// For public clients OR clients with attestation config, add the privileged client to audience for token introspection
	h.log.Printf("🔍 [REGISTRATION] Checking privileged client addition: isPublic=%v, hasAttestation=%v, config=%v, privileged_id='%s'", isPublic, finalAttestationConfig != nil, h.config != nil, h.config.Security.PrivilegedClientID)
	if h.config != nil && h.config.Security.PrivilegedClientID != "" {
		if !contains(audience, h.config.Security.PrivilegedClientID) {
			audience = append(audience, h.config.Security.PrivilegedClientID)
			h.log.Printf("🔍 [REGISTRATION] Added privileged client %s to audience for client: %v", h.config.Security.PrivilegedClientID, audience)
		} else {
			h.log.Printf("🔍 [REGISTRATION] Privileged client %s already in audience", h.config.Security.PrivilegedClientID)
		}
	}

	h.log.Printf("🔍 [REGISTRATION] Final client scopes: %v", scopes)
	h.log.Printf("🔍 [REGISTRATION] Final client audience: %v", audience)

	// Convert claims string to array if provided
	var claims []string
	if metadata.Claims != "" {
		claims = splitScope(metadata.Claims) // Reuse splitScope function for claims
		h.log.Printf("🔍 [REGISTRATION] Split claims string '%s' into: %v", metadata.Claims, claims)
	} else {
		h.log.Printf("🔍 [REGISTRATION] No claims provided")
	}

	h.log.Printf("🔍 [REGISTRATION] Final client claims: %v", claims)

	// Create or update the client
	h.log.Printf("🔍 [REGISTRATION] Creating store.CustomClient")
	var clientSecretBytes []byte
	if isPublic {
		clientSecretBytes = nil
	} else {
		clientSecretBytes = hashedSecret
	}
	newClient := &store.CustomClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        clientSecretBytes,
			RedirectURIs:  metadata.RedirectURIs,
			GrantTypes:    grantTypes,
			ResponseTypes: responseTypes,
			Scopes:        scopes,
			Audience:      audience,
			Public:        isPublic,
		},
		Claims:              claims,
		ForceAuthentication: metadata.ForceAuthentication,
		ForceConsent:        metadata.ForceConsent,
	}
	h.log.Printf("✅ [REGISTRATION] store.CustomClient created successfully")
	h.log.Printf("🔍 [REGISTRATION] Client details: ID=%s, Public=%v, GrantTypes=%v, ResponseTypes=%v, Scopes=%v, Claims=%v, Audience=%v",
		newClient.ID, newClient.Public, newClient.GrantTypes, newClient.ResponseTypes, newClient.Scopes, newClient.Claims, newClient.Audience)

	// Store the client
	h.log.Printf("🔍 [REGISTRATION] Storing client in storage")
	if isUpdate {
		if err := h.storage.UpdateClient(r.Context(), clientID, newClient); err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to update client: %v", err)
			http.Error(w, "Failed to update client", http.StatusInternalServerError)
			return
		}
		h.log.Printf("✅ [REGISTRATION] Client updated successfully")
	} else {
		if err := h.storage.CreateClient(r.Context(), newClient); err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to create client: %v", err)
			http.Error(w, "Failed to create client", http.StatusInternalServerError)
			return
		}
		h.log.Printf("✅ [REGISTRATION] Client created successfully")
	}

	// Register attestation config with the attestation manager if provided
	if finalAttestationConfig != nil {
		h.log.Printf("🔍 [REGISTRATION] Registering attestation config with attestation manager")
		h.attestationManager.AddClientConfig(clientID, finalAttestationConfig)
		h.log.Printf("✅ [REGISTRATION] Attestation config registered with attestation manager")
	}

	// Store the original secret for dynamic clients (only for new clients, not updates, and not for public clients)
	if !isUpdate && !isPublic && clientSecret != "" {
		// Encrypt and store the secret
		encryptedSecret, err := h.secretManager.EncryptSecret(clientSecret)
		if err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to encrypt client secret: %v", err)
			http.Error(w, "Failed to encrypt client secret", http.StatusInternalServerError)
			return
		}

		if err := h.storage.StoreClientSecret(r.Context(), clientID, encryptedSecret); err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to store encrypted client secret: %v", err)
			http.Error(w, "Failed to store client secret", http.StatusInternalServerError)
			return
		}
		h.log.Printf("✅ [REGISTRATION] Encrypted client secret stored for client: %s", clientID)
	}

	// Store the attestation config for dynamic clients
	if finalAttestationConfig != nil {
		if err := h.storage.StoreAttestationConfig(r.Context(), clientID, finalAttestationConfig); err != nil {
			h.log.Errorf("❌ [REGISTRATION] Failed to store attestation config: %v", err)
			http.Error(w, "Failed to store attestation config", http.StatusInternalServerError)
			return
		}
		h.log.Printf("✅ [REGISTRATION] Attestation config stored for client: %s", clientID)
	}

	// Prepare the response
	h.log.Printf("🔍 [REGISTRATION] Preparing response")
	now := time.Now().Unix()
	var responseSecret string
	if isPublic {
		responseSecret = "" // Don't return secret for public clients
	} else {
		responseSecret = clientSecret
	}
	response := ClientResponse{
		ClientID:                clientID,
		ClientSecret:            responseSecret,
		ClientSecretExpiresAt:   0, // 0 means no expiration
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
		Claims:                  strings.Join(claims, " "),
		Contacts:                metadata.Contacts,
		TermsOfServiceURI:       metadata.TermsOfServiceURI,
		PolicyURI:               metadata.PolicyURI,
		JwksURI:                 metadata.JwksURI,
		Jwks:                    metadata.Jwks,
		SoftwareID:              metadata.SoftwareID,
		SoftwareVersion:         metadata.SoftwareVersion,
		ForceAuthentication:     metadata.ForceAuthentication,
		ForceConsent:            metadata.ForceConsent,
		Audience:                audience,
		AttestationConfig:       finalAttestationConfig,
		Public:                  isPublic,
	}
	h.log.Printf("✅ [REGISTRATION] Response prepared successfully")

	if isUpdate {
		h.log.Printf("✅ [REGISTRATION] Updated existing client: %s", clientID)
	} else {
		h.log.Printf("✅ [REGISTRATION] Registered new client: %s", clientID)
	}

	// Return the response
	h.log.Printf("🔍 [REGISTRATION] Setting response headers and encoding JSON")
	w.Header().Set("Content-Type", "application/json")
	if isUpdate {
		w.WriteHeader(http.StatusOK)
		h.log.Printf("🔍 [REGISTRATION] Set status code to 200 (OK)")
	} else {
		w.WriteHeader(http.StatusCreated)
		h.log.Printf("🔍 [REGISTRATION] Set status code to 201 (Created)")
	}

	h.log.Printf("🔍 [REGISTRATION] Encoding response JSON")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Errorf("❌ [REGISTRATION] Failed to encode response JSON: %v", err)
		// Can't send error response here as headers are already written
		return
	}

	h.log.Printf("✅ [REGISTRATION] Client Secret: %s", clientSecret)
	h.log.Printf("✅ [REGISTRATION] Response JSON encoded and sent successfully")
	h.log.Printf("🎉 [REGISTRATION] Client registration completed successfully")
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

// resolveTrustAnchors validates that trust anchor names can be resolved to existing files
func (h *RegistrationHandler) resolveTrustAnchors(ctx context.Context, attestationConfig *config.ClientAttestationConfig) error {
	if h.trustAnchorHandler == nil {
		return fmt.Errorf("trust anchor handler not available")
	}

	for _, name := range attestationConfig.TrustAnchors {
		_, err := h.trustAnchorHandler.ResolvePath(ctx, name)
		if err != nil {
			return fmt.Errorf("trust anchor not found: %s", name)
		}
	}

	// Trust anchors remain as names, not paths
	return nil
}

// GetClientSecret retrieves the original unhashed client secret for a given client ID
func GetClientSecret(ctx context.Context, clientID string, storage store.Storage, secretManager *store.SecretManager) (string, bool) {
	encryptedSecret, err := storage.GetClientSecret(ctx, clientID)
	if err != nil {
		return "", false
	}

	decryptedSecret, err := secretManager.DecryptSecret(encryptedSecret)
	if err != nil {
		return "", false
	}

	return decryptedSecret, true
}

// GetClientAttestationConfig retrieves the attestation config for a given client ID
func GetClientAttestationConfig(ctx context.Context, clientID string, storage store.Storage) (*config.ClientAttestationConfig, bool) {
	config, err := storage.GetAttestationConfig(ctx, clientID)
	if err != nil {
		return nil, false
	}
	return config, true
}
