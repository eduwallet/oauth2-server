package handlers

import (
	"encoding/json"
	"fmt"
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

	homeHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OAuth2 Server</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
		.container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		h1 { color: #333; text-align: center; margin-bottom: 30px; }
		.section { margin-bottom: 30px; padding: 20px; background-color: #f8f9fa; border-radius: 6px; }
		.btn { display: inline-block; padding: 10px 20px; margin: 5px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; }
		.btn:hover { background-color: #0056b3; }
		.endpoint { font-family: monospace; background-color: #e9ecef; padding: 8px; border-radius: 3px; }
		ul { margin: 10px 0; }
		li { margin: 8px 0; }
		code { background-color: #f1f3f4; padding: 2px 4px; border-radius: 2px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>🚀 OAuth2 Authorization Server</h1>
		
		<div class="section">
			<h2>📋 Server Information</h2>
			<p><strong>Base URL:</strong> %s</p>
			<p><strong>Version:</strong> Development</p>
			<p><strong>Status:</strong> ✅ Running</p>
		</div>

		<div class="section">
			<h3>📚 API Endpoints</h3>
			<ul>
				<li><span class="endpoint">GET /.well-known/oauth-authorization-server</span> - OAuth2 Discovery</li>
				<li><span class="endpoint">GET /.well-known/openid-configuration</span> - OIDC Discovery</li>
				<li><span class="endpoint">GET /.well-known/jwks.json</span> - JWKS</li>
				<li><span class="endpoint">GET /health</span> - Health</li>
				<li><span class="endpoint">GET /stats</span> - Server Stats</li>
			</ul>
		</div>

		<!-- Fancy Server Stats Section -->
		<div class="stats-section" style="margin-top:30px;">
		  <h2 style="text-align:center;">🚦 Server Stats</h2>
		  <div id="stats-cards" style="display:flex; gap:24px; justify-content:center; flex-wrap:wrap; margin-top:20px;">
		    <div class="stat-card" id="stat-tokens">
		      <div class="stat-icon">🔑</div>
		      <div class="stat-label">Tokens</div>
		      <div class="stat-value" id="stats-tokens-value">...</div>
		    </div>
		    <div class="stat-card" id="stat-clients">
		      <div class="stat-icon">🧩</div>
		      <div class="stat-label">Clients</div>
		      <div class="stat-value" id="stats-clients-value">...</div>
		    </div>
		    <div class="stat-card" id="stat-users">
		      <div class="stat-icon">👤</div>
		      <div class="stat-label">Users</div>
		      <div class="stat-value" id="stats-users-value">...</div>
		    </div>
		  </div>
		</div>
		<style>
		  .stat-card {
		    background: #fff;
		    border-radius: 12px;
		    box-shadow: 0 2px 8px rgba(0,0,0,0.07);
		    padding: 24px 32px;
		    min-width: 140px;
		    text-align: center;
		    transition: box-shadow 0.2s;
		  }
		  .stat-card:hover {
		    box-shadow: 0 4px 16px rgba(0,0,0,0.13);
		  }
		  .stat-icon {
		    font-size: 2.2em;
		    margin-bottom: 8px;
		  }
		  .stat-label {
		    font-size: 1.1em;
		    color: #555;
		    margin-bottom: 6px;
		    font-weight: 500;
		  }
		  .stat-value {
		    font-size: 2em;
		    font-weight: bold;
		    color: #007bff;
		  }
		</style>
		<script>
		function loadStats() {
		  fetch('/stats')
		    .then(r => r.json())
		    .then(stats => {
		      // Use the correct attribute for tokens
		      document.getElementById('stats-tokens-value').innerText =
		        stats.tokens?.tokens?.total ?? (typeof stats.tokens.tokens.total === "number" ? stats.tokens.tokens.total : "—");
		      document.getElementById('stats-clients-value').innerText =
		        stats.clients?.total ?? (typeof stats.clients === "number" ? stats.clients : "—");
		      document.getElementById('stats-users-value').innerText =
		        stats.users?.total ?? (typeof stats.users === "number" ? stats.users : stats.users ?? "—");
		    })
		    .catch(() => {
		      document.getElementById('stats-tokens-value').innerText = '—';
		      document.getElementById('stats-clients-value').innerText = '—';
		      document.getElementById('stats-users-value').innerText = '—';
		    });
		}
		document.addEventListener('DOMContentLoaded', loadStats);
		</script>
	</div>
</body>
</html>`, h.Config.Server.BaseURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(homeHTML))
}
