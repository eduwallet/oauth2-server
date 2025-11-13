package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/attestation"
	"oauth2-server/pkg/config"
)

// OAuth2DiscoveryHandler manages OAuth2 Authorization Server Metadata requests (RFC 8414)
type OAuth2DiscoveryHandler struct {
	Configuration      *config.Config
	AttestationManager *attestation.VerifierManager
}

// NewOAuth2DiscoveryHandler creates a new OAuth2 discovery handler
func NewOAuth2DiscoveryHandler(configuration *config.Config, attestationManager *attestation.VerifierManager) *OAuth2DiscoveryHandler {
	return &OAuth2DiscoveryHandler{
		Configuration:      configuration,
		AttestationManager: attestationManager,
	}
}

// TODO: More granular merging of upstream and local metadata if needed

// ServeHTTP handles OAuth2 Authorization Server Metadata requests (/.well-known/oauth-authorization-server)
func (h *OAuth2DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	var upstream map[string]interface{} = nil

	// Check if proxy mode is enabled
	if h.Configuration.IsProxyMode() {
		upstream = h.Configuration.UpstreamProvider.Metadata
		if upstream == nil {
			http.Error(w, "upstream provider not configured", http.StatusBadGateway)
			return
		}
	}

	// Start with our local OAuth2 discovery metadata
	baseURL := h.Configuration.GetEffectiveBaseURL(r)

	// OAuth2 Authorization Server Metadata (RFC 8414)
	oauth2Metadata := map[string]interface{}{
		// Required fields
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":         baseURL + "/token",
		"jwks_uri":               baseURL + "/.well-known/jwks.json",

		// Optional but recommended fields
		"registration_endpoint":  baseURL + "/register",
		"revocation_endpoint":    baseURL + "/revoke",
		"introspection_endpoint": baseURL + "/introspect",
		"userinfo_endpoint":      baseURL + "/userinfo",

		// Device Flow (RFC 8628)
		"device_authorization_endpoint": baseURL + "/device/authorize",

		// Supported response types
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},

		// Supported grant types
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// Token Exchange specific metadata (RFC 8693)
		"token_exchange_grant_types_supported": []string{
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		"subject_token_types_supported": []string{
			"urn:ietf:params:oauth:token-type:access_token",
			"urn:ietf:params:oauth:token-type:refresh_token",
			"urn:ietf:params:oauth:token-type:id_token",
		},

		"actor_token_types_supported": []string{
			"urn:ietf:params:oauth:token-type:access_token",
		},

		// Supported scopes - TAKEN FROM UPSTREAM
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
			"offline_access",
			"api:read",
			"api:write",
			"admin",
		},

		// Token endpoint authentication methods
		"token_endpoint_auth_methods_supported": h.getTokenEndpointAuthMethods(),

		// Token endpoint signing algorithms - TAKEN FROM UPSTREAM
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256",
			"HS256",
		},

		// PKCE support - TAKEN FROM UPSTREAM
		"code_challenge_methods_supported": []string{
			"plain",
			"S256",
		},

		// Introspection endpoint authentication methods
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},

		// Revocation endpoint authentication methods
		"revocation_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},

		// Additional capabilities
		"response_modes_supported": []string{
			"query",
			"fragment",
			"form_post",
		},

		// Service documentation
		"service_documentation": baseURL + "/docs",
		"op_policy_uri":         baseURL + "/policy",
		"op_tos_uri":            baseURL + "/terms",
	}

	if upstream != nil {
		// scopes_supported
		if upstreamScopes, ok := upstream["scopes_supported"]; ok {
			oauth2Metadata["scopes_supported"] = upstreamScopes
		}

		// code_challenge_methods_supported
		if upstreamPKCE, ok := upstream["code_challenge_methods_supported"]; ok {
			oauth2Metadata["code_challenge_methods_supported"] = upstreamPKCE
		}

		// token_endpoint_auth_signing_alg_values_supported
		if upstreamSigningAlgs, ok := upstream["token_endpoint_auth_signing_alg_values_supported"]; ok {
			oauth2Metadata["token_endpoint_auth_signing_alg_values_supported"] = upstreamSigningAlgs
		}
	}

	// Return the merged OAuth2 discovery metadata
	json.NewEncoder(w).Encode(oauth2Metadata)
}

// getTokenEndpointAuthMethods returns the supported token endpoint authentication methods
func (h *OAuth2DiscoveryHandler) getTokenEndpointAuthMethods() []string {
	methods := []string{
		"client_secret_basic",
		"client_secret_post",
		"private_key_jwt",
		"client_secret_jwt",
		"none",
	}

	// Add attestation methods if attestation is enabled
	if h.Configuration.Attestation.Enabled && h.AttestationManager != nil {
		attestationMethods := h.getAttestationMethods()
		methods = append(methods, attestationMethods...)
	}

	return methods
}

// getAttestationMethods returns the supported attestation authentication methods
func (h *OAuth2DiscoveryHandler) getAttestationMethods() []string {
	var methods []string

	// Collect all unique attestation methods from configured clients
	methodSet := make(map[string]bool)

	for _, client := range h.Configuration.Attestation.Clients {
		for _, method := range client.AllowedMethods {
			methodSet[method] = true
		}
	}

	// Convert set to slice
	for method := range methodSet {
		methods = append(methods, method)
	}

	return methods
}
