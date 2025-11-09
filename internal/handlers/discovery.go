package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/pkg/config"
)

// DiscoveryHandler manages OpenID Connect Discovery requests (/.well-known/openid-configuration)
type DiscoveryHandler struct {
	Configuration *config.Config
}

// NewDiscoveryHandler creates a new discovery handler
func NewDiscoveryHandler(configuration *config.Config) *DiscoveryHandler {
	return &DiscoveryHandler{
		Configuration: configuration,
	}
}

// ServeHTTP handles OpenID Connect Discovery requests
func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	// Get the effective base URL (proxy-aware)
	baseURL := h.Configuration.GetEffectiveBaseURL(r)

	wellKnown := map[string]interface{}{
		// OAuth2 Authorization Server Metadata (RFC 8414)
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/oauth/authorize",
		"token_endpoint":         baseURL + "/oauth/token",
		"jwks_uri":               baseURL + "/.well-known/jwks.json",
		"registration_endpoint":  baseURL + "/register",
		"revocation_endpoint":    baseURL + "/oauth/revoke",
		"introspection_endpoint": baseURL + "/oauth/introspect",
		"userinfo_endpoint":      baseURL + "/userinfo",

		// Device Flow (RFC 8628)
		"device_authorization_endpoint":    baseURL + "/device/authorize",
		"device_verification_uri":          baseURL + "/device",
		"device_verification_uri_complete": baseURL + "/device?user_code={user_code}",

		// Supported scopes
		"scopes_supported": []string{
			"openid", "profile", "email", "offline_access",
			"api:read", "api:write", "admin",
		},

		// Supported response types
		"response_types_supported": []string{
			"code", "token", "id_token",
			"code token", "code id_token", "token id_token",
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

		// Token endpoint authentication methods
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"client_secret_jwt",
			"none",
		},

		// Token endpoint signing algorithms
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		// PKCE support
		"code_challenge_methods_supported": []string{
			"plain", "S256",
		},

		// OpenID Connect specific metadata
		"subject_types_supported": []string{
			"public", "pairwise",
		},

		"id_token_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		"id_token_encryption_alg_values_supported": []string{
			"RSA1_5", "RSA-OAEP", "A128KW", "A192KW", "A256KW",
		},

		"id_token_encryption_enc_values_supported": []string{
			"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
			"A128GCM", "A192GCM", "A256GCM",
		},

		"userinfo_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		"request_object_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		"response_modes_supported": []string{
			"query", "fragment", "form_post",
		},

		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website",
			"email", "email_verified", "gender", "birthdate", "zoneinfo",
			"locale", "phone_number", "phone_number_verified", "address",
			"updated_at",
		},

		"claims_parameter_supported":            true,
		"request_parameter_supported":           true,
		"request_uri_parameter_supported":       false,
		"require_request_uri_registration":      false,
		"claims_locales_supported":              []string{"en-US", "en-GB", "de-DE", "fr-FR"},
		"ui_locales_supported":                  []string{"en-US", "en-GB", "de-DE", "fr-FR"},
		"display_values_supported":              []string{"page", "popup", "touch", "wap"},
		"acr_values_supported":                  []string{"0", "1", "2"},
		"frontchannel_logout_supported":         true,
		"frontchannel_logout_session_supported": true,
		"backchannel_logout_supported":          false,
		"backchannel_logout_session_supported":  false,

		// Additional OAuth2 features
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic", "client_secret_post",
		},

		"revocation_endpoint_auth_methods_supported": []string{
			"client_secret_basic", "client_secret_post",
		},

		"op_policy_uri": baseURL + "/policy",
		"op_tos_uri":    baseURL + "/terms",
	}

	json.NewEncoder(w).Encode(wellKnown)
}
