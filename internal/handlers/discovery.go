package handlers

import (
	"encoding/json"
	"net/http"
)

// HandleOAuthDiscovery handles OAuth2 authorization server metadata discovery (RFC 8414)
func (h *Handlers) HandleOAuthDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                        h.Config.Server.BaseURL,
		"authorization_endpoint":        h.Config.Server.BaseURL + "/oauth2/auth",
		"token_endpoint":                h.Config.Server.BaseURL + "/oauth2/token",
		"userinfo_endpoint":             h.Config.Server.BaseURL + "/oauth2/userinfo",
		"introspection_endpoint":        h.Config.Server.BaseURL + "/oauth2/introspect",
		"revocation_endpoint":           h.Config.Server.BaseURL + "/oauth2/revoke",
		"registration_endpoint":         h.Config.Server.BaseURL + "/oauth2/register",
		"device_authorization_endpoint": h.Config.Server.BaseURL + "/device/code",
		"jwks_uri":                      h.Config.Server.BaseURL + "/.well-known/jwks.json",
		"response_types_supported":      []string{"code", "token", "id_token"},
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
		"scopes_supported":                 []string{"openid", "profile", "email"},
		"code_challenge_methods_supported": []string{"S256", "plain"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

// HandleOpenIDDiscovery handles OpenID Connect discovery
func (h *Handlers) HandleOpenIDDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                        h.Config.Server.BaseURL,
		"authorization_endpoint":        h.Config.Server.BaseURL + "/oauth2/auth",
		"token_endpoint":                h.Config.Server.BaseURL + "/oauth2/token",
		"userinfo_endpoint":             h.Config.Server.BaseURL + "/oauth2/userinfo",
		"jwks_uri":                      h.Config.Server.BaseURL + "/.well-known/jwks.json",
		"registration_endpoint":         h.Config.Server.BaseURL + "/oauth2/register",
		"introspection_endpoint":        h.Config.Server.BaseURL + "/oauth2/introspect",
		"device_authorization_endpoint": h.Config.Server.BaseURL + "/device/code",
		"scopes_supported":              []string{"openid", "profile", "email"},
		"response_types_supported":      []string{"code", "id_token", "token id_token", "code id_token", "code token", "code id_token token"},
		"response_modes_supported":      []string{"query", "fragment"},
		"grant_types_supported": []string{
			"authorization_code",
			"implicit",
			"refresh_token",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "name", "given_name",
			"family_name", "nickname", "preferred_username", "email",
			"email_verified", "picture", "website",
		},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"userinfo_signing_alg_values_supported": []string{"none"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

// HandleJWKS handles JWKS endpoint
func (h *Handlers) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]interface{}{
		"keys": []interface{}{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// HandleRoot handles the root endpoint
func (h *Handlers) HandleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
        <h1>🔐 OAuth2 Server</h1>
        <p>Server is running and ready to serve OAuth2 requests</p>
        <ul>
            <li><a href="/.well-known/oauth-authorization-server">OAuth2 Discovery</a></li>
            <li><a href="/.well-known/openid-configuration">OpenID Connect Discovery</a></li>
            <li><a href="/.well-known/jwks.json">JWKS</a></li>
        </ul>
    `))
}
