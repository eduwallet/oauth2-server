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

	var upstream map[string]interface{} = nil

	// Check if proxy mode is enabled
	if h.Configuration.IsProxyMode() {
		upstream = h.Configuration.UpstreamProvider.Metadata
		if upstream == nil {
			http.Error(w, "Internal server error: No upstream metadata", http.StatusInternalServerError)
			return
		}
	}

	// Start with our local discovery metadata
	baseURL := h.Configuration.GetEffectiveBaseURL(r)

	wellKnown := map[string]interface{}{
		// OAuth2 Authorization Server Metadata (RFC 8414)
		"issuer":                               baseURL,
		"authorization_endpoint":               baseURL + "/authorize",
		"token_endpoint":                       baseURL + "/token",
		"jwks_uri":                             baseURL + "/.well-known/jwks.json",
		"registration_endpoint":                baseURL + "/register",
		"revocation_endpoint":                  baseURL + "/revoke",
		"introspection_endpoint":               baseURL + "/introspect",
		"userinfo_endpoint":                    baseURL + "/userinfo",
		"authorization_introspection_endpoint": baseURL + "/authorization-introspection",

		// Device Flow (RFC 8628)
		"device_authorization_endpoint":    baseURL + "/device/authorize",
		"device_verification_uri":          baseURL + "/device",
		"device_verification_uri_complete": baseURL + "/device?user_code={user_code}",

		// Supported scopes - TAKEN FROM UPSTREAM
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

		// Token endpoint signing algorithms - TAKEN FROM UPSTREAM
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256", "HS256",
		},

		// PKCE support - TAKEN FROM UPSTREAM
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

	if upstream != nil {
		// scopes_supported
		if upstreamScopes, ok := upstream["scopes_supported"]; ok {
			wellKnown["scopes_supported"] = upstreamScopes
		}

		// claims_supported
		if upstreamClaims, ok := upstream["claims_supported"]; ok {
			wellKnown["claims_supported"] = upstreamClaims
		}

		// response_types_supported
		if upstreamResponseTypes, ok := upstream["response_types_supported"]; ok {
			wellKnown["response_types_supported"] = upstreamResponseTypes
		}

		// grant_types_supported - merge with our token-exchange grant type
		if upstreamGrantTypes, ok := upstream["grant_types_supported"]; ok {
			if grantTypesList, ok := upstreamGrantTypes.([]interface{}); ok {
				// Add upstream grant types
				mergedGrantTypes := make([]string, 0, len(grantTypesList)+1)
				for _, gt := range grantTypesList {
					if gtStr, ok := gt.(string); ok {
						mergedGrantTypes = append(mergedGrantTypes, gtStr)
					}
				}
				// Add our token-exchange grant type if not already present
				hasTokenExchange := false
				for _, gt := range mergedGrantTypes {
					if gt == "urn:ietf:params:oauth:grant-type:token-exchange" {
						hasTokenExchange = true
						break
					}
				}
				if !hasTokenExchange {
					mergedGrantTypes = append(mergedGrantTypes, "urn:ietf:params:oauth:grant-type:token-exchange")
				}
				wellKnown["grant_types_supported"] = mergedGrantTypes
			}
		}

		// code_challenge_methods_supported
		if upstreamPKCE, ok := upstream["code_challenge_methods_supported"]; ok {
			wellKnown["code_challenge_methods_supported"] = upstreamPKCE
		}

		// subject_types_supported
		if upstreamSubjectTypes, ok := upstream["subject_types_supported"]; ok {
			wellKnown["subject_types_supported"] = upstreamSubjectTypes
		}

		// id_token_signing_alg_values_supported
		if upstreamIDTokenSigningAlgs, ok := upstream["id_token_signing_alg_values_supported"]; ok {
			wellKnown["id_token_signing_alg_values_supported"] = upstreamIDTokenSigningAlgs
		}

		// id_token_encryption_alg_values_supported
		if upstreamIDTokenEncryptionAlgs, ok := upstream["id_token_encryption_alg_values_supported"]; ok {
			wellKnown["id_token_encryption_alg_values_supported"] = upstreamIDTokenEncryptionAlgs
		}

		// id_token_encryption_enc_values_supported
		if upstreamIDTokenEncryptionEnc, ok := upstream["id_token_encryption_enc_values_supported"]; ok {
			wellKnown["id_token_encryption_enc_values_supported"] = upstreamIDTokenEncryptionEnc
		}

		// userinfo_signing_alg_values_supported
		if upstreamUserInfoSigningAlgs, ok := upstream["userinfo_signing_alg_values_supported"]; ok {
			wellKnown["userinfo_signing_alg_values_supported"] = upstreamUserInfoSigningAlgs
		}

		// response_modes_supported
		if upstreamResponseModes, ok := upstream["response_modes_supported"]; ok {
			wellKnown["response_modes_supported"] = upstreamResponseModes
		}

		// token_endpoint_auth_methods_supported
		if upstreamTokenAuthMethods, ok := upstream["token_endpoint_auth_methods_supported"]; ok {
			wellKnown["token_endpoint_auth_methods_supported"] = upstreamTokenAuthMethods
		}

		// token_endpoint_auth_signing_alg_values_supported
		if upstreamSigningAlgs, ok := upstream["token_endpoint_auth_signing_alg_values_supported"]; ok {
			wellKnown["token_endpoint_auth_signing_alg_values_supported"] = upstreamSigningAlgs
		}

		// acr_values_supported
		if upstreamACRValues, ok := upstream["acr_values_supported"]; ok {
			wellKnown["acr_values_supported"] = upstreamACRValues
		}

		// display_values_supported
		if upstreamDisplayValues, ok := upstream["display_values_supported"]; ok {
			wellKnown["display_values_supported"] = upstreamDisplayValues
		}

		// claim_types_supported
		if upstreamClaimTypes, ok := upstream["claim_types_supported"]; ok {
			wellKnown["claim_types_supported"] = upstreamClaimTypes
		}

		// claims_locales_supported
		if upstreamClaimsLocales, ok := upstream["claims_locales_supported"]; ok {
			wellKnown["claims_locales_supported"] = upstreamClaimsLocales
		}

		// ui_locales_supported
		if upstreamUILocales, ok := upstream["ui_locales_supported"]; ok {
			wellKnown["ui_locales_supported"] = upstreamUILocales
		}
	}

	// Return the merged discovery metadata
	json.NewEncoder(w).Encode(wellKnown)
}
