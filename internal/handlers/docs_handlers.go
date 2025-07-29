package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"path/filepath"
)

// DocsHandler provides interactive API documentation
// --- OAuth2 Flow Endpoint Generators for API Explorer ---

// generateAuthorizationCodeEndpoints creates HTML for the Authorization Code flow
func (h *DocsHandler) generateAuthorizationCodeEndpoints() string {
	return `
    <div class="endpoint-card">
      <div class="endpoint-summary">
        <span class="method get">GET</span>
        <span style="margin-right:12px;">/auth</span>
        <span>Authorization Code Flow</span>
      </div>
      <div class="endpoint-details">
        <div style="margin-bottom:10px;">
          <strong>Description:</strong> Start the authorization code flow (user login & consent).
        </div>
        <form class="swagger-form" onsubmit="event.preventDefault(); tryAuthCodeFlow(this);">
          <div class="form-group">
            <label>client_id</label>
            <input name="client_id" value="frontend-app" required>
          </div>
          <div class="form-group">
            <label>redirect_uri</label>
            <input name="redirect_uri" value="http://localhost:8080/callback" required>
          </div>
          <div class="form-group">
            <label>scope</label>
            <input name="scope" value="openid profile email api:read">
          </div>
          <div class="form-group">
            <label>response_type</label>
            <input name="response_type" value="code">
          </div>
          <button type="submit" class="try-btn">Try it out</button>
        </form>
        <div class="request-response" id="authcode-response" style="display:none;"></div>
      </div>
    </div>
    <script>
    function tryAuthCodeFlow(form) {
      // Build query string
      var params = new URLSearchParams();
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (el.name && el.value) params.append(el.name, el.value);
      }
      var url = '/auth?' + params.toString();
      // Show curl
      var curl = 'curl -X GET "' + window.location.origin + url + '"';
      var respDiv = document.getElementById('authcode-response');
      respDiv.style.display = 'block';
      respDiv.textContent = 'Request: ' + curl + '\n\nRedirecting to: ' + url;
      // Actually redirect for real auth flow
      window.location.href = url;
    }
    </script>
`
}

// generateClientCredentialsEndpoints creates HTML for the Client Credentials flow
func (h *DocsHandler) generateClientCredentialsEndpoints() string {
	return `
    <div class="endpoint-card">
      <div class="endpoint-summary">
        <span class="method post">POST</span>
        <span style="margin-right:12px;">/token</span>
        <span>Client Credentials Flow</span>
      </div>
      <div class="endpoint-details">
        <div style="margin-bottom:10px;">
          <strong>Description:</strong> Obtain an access token using client credentials.
        </div>
        <form class="swagger-form" onsubmit="event.preventDefault(); tryClientCredsFlow(this);">
          <div class="form-group">
            <label>client_id</label>
            <input name="client_id" value="backend-client" required>
          </div>
          <div class="form-group">
            <label>client_secret</label>
            <input name="client_secret" value="backend-client-secret" required>
          </div>
          <div class="form-group">
            <label>grant_type</label>
            <input name="grant_type" value="client_credentials">
          </div>
          <div class="form-group">
            <label>scope</label>
            <input name="scope" value="api:read api:write">
          </div>
          <button type="submit" class="try-btn">Try it out</button>
        </form>
        <div class="request-response" id="clientcreds-response" style="display:none;"></div>
      </div>
    </div>
    <script>
    function tryClientCredsFlow(form) {
      var params = new URLSearchParams();
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (el.name && el.value) params.append(el.name, el.value);
      }
      var url = '/token';
      var curl = 'curl -X POST "' + window.location.origin + url + '" -d "' + params.toString().replace(/&/g, '" -d "') + '"';
      var respDiv = document.getElementById('clientcreds-response');
      respDiv.style.display = 'block';
      respDiv.textContent = 'Request: ' + curl + '\n\n';
      fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params })
        .then(r => r.text())
        .then(txt => { respDiv.textContent += 'Response:\n' + txt; })
        .catch(e => { respDiv.textContent += 'Error: ' + e; });
    }
    </script>
    `
}

// generateRefreshTokenEndpoints creates HTML for the Refresh Token flow
func (h *DocsHandler) generateRefreshTokenEndpoints() string {
	return `
    <div class="endpoint-card">
      <div class="endpoint-summary">
        <span class="method post">POST</span>
        <span style="margin-right:12px;">/token</span>
        <span>Refresh Token Flow</span>
      </div>
      <div class="endpoint-details">
        <div style="margin-bottom:10px;">
          <strong>Description:</strong> Exchange a refresh token for a new access token.
        </div>
        <form class="swagger-form" onsubmit="event.preventDefault(); tryRefreshTokenFlow(this);">
          <div class="form-group">
            <label>client_id</label>
            <input name="client_id" value="frontend-app" required>
          </div>
          <div class="form-group">
            <label>client_secret</label>
            <input name="client_secret" value="frontend-client-secret" required>
          </div>
          <div class="form-group">
            <label>grant_type</label>
            <input name="grant_type" value="refresh_token">
          </div>
          <div class="form-group">
            <label>refresh_token</label>
            <input name="refresh_token" value="">
          </div>
          <button type="submit" class="try-btn">Try it out</button>
        </form>
        <div class="request-response" id="refresh-response" style="display:none;"></div>
      </div>
    </div>
    <script>
    function tryRefreshTokenFlow(form) {
      var params = new URLSearchParams();
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (el.name && el.value) params.append(el.name, el.value);
      }
      var url = '/token';
      var curl = 'curl -X POST "' + window.location.origin + url + '" -d "' + params.toString().replace(/&/g, '" -d "') + '"';
      var respDiv = document.getElementById('refresh-response');
      respDiv.style.display = 'block';
      respDiv.textContent = 'Request: ' + curl + '\n\n';
      fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params })
        .then(r => r.text())
        .then(txt => { respDiv.textContent += 'Response:\n' + txt; })
        .catch(e => { respDiv.textContent += 'Error: ' + e; });
    }
    </script>
    `
}

// generateTokenExchangeEndpoints creates HTML for the Token Exchange flow
func (h *DocsHandler) generateTokenExchangeEndpoints() string {
	return `
    <div class="endpoint-card">
      <div class="endpoint-summary">
        <span class="method post">POST</span>
        <span style="margin-right:12px;">/token</span>
        <span>Token Exchange Flow</span>
      </div>
      <div class="endpoint-details">
        <div style="margin-bottom:10px;">
          <strong>Description:</strong> Exchange a subject token for a new token (RFC 8693).
        </div>
        <form class="swagger-form" onsubmit="event.preventDefault(); tryTokenExchangeFlow(this);">
          <div class="form-group">
            <label>client_id</label>
            <input name="client_id" value="backend-client" required>
          </div>
          <div class="form-group">
            <label>client_secret</label>
            <input name="client_secret" value="backend-client-secret" required>
          </div>
          <div class="form-group">
            <label>grant_type</label>
            <input name="grant_type" value="urn:ietf:params:oauth:grant-type:token-exchange">
          </div>
          <div class="form-group">
            <label>subject_token</label>
            <input name="subject_token" value="">
          </div>
          <div class="form-group">
            <label>subject_token_type</label>
            <input name="subject_token_type" value="urn:ietf:params:oauth:token-type:access_token">
          </div>
          <div class="form-group">
            <label>audience</label>
            <input name="audience" value="downstream-service">
          </div>
          <button type="submit" class="try-btn">Try it out</button>
        </form>
        <div class="request-response" id="tokenexchange-response" style="display:none;"></div>
      </div>
    </div>
    <script>
    function tryTokenExchangeFlow(form) {
      var params = new URLSearchParams();
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (el.name && el.value) params.append(el.name, el.value);
      }
      var url = '/token';
      var curl = 'curl -X POST "' + window.location.origin + url + '" -d "' + params.toString().replace(/&/g, '" -d "') + '"';
      var respDiv = document.getElementById('tokenexchange-response');
      respDiv.style.display = 'block';
      respDiv.textContent = 'Request: ' + curl + '\n\n';
      fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params })
        .then(r => r.text())
        .then(txt => { respDiv.textContent += 'Response:\n' + txt; })
        .catch(e => { respDiv.textContent += 'Error: ' + e; });
    }
    </script>
    `
}

type DocsHandler struct {
	config      *config.Config
	clientStore *store.ClientStore
}

// NewDocsHandler creates a new documentation handler
func NewDocsHandler(cfg *config.Config, clientStore *store.ClientStore) *DocsHandler {
	return &DocsHandler{
		config:      cfg,
		clientStore: clientStore,
	}
}

// ServeHTTP handles the documentation endpoint
func (h *DocsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[DocsHandler] ServeHTTP called for path: %s\n", r.URL.Path)
	if r.URL.Path == "/docs" {
		fmt.Println("[DocsHandler] Serving docs UI")
		h.serveDocs(w, r)
		return
	}

	if r.URL.Path == "/docs/api.json" {
		fmt.Println("[DocsHandler] Serving OpenAPI spec")
		h.serveOpenAPISpec(w, r)
		return
	}

	// Handle client management API endpoints
	if r.URL.Path == "/docs/api/clients" {
		fmt.Println("[DocsHandler] Serving clients API list")
		h.HandleClientsAPI(w, r)
		return
	}

	if len(r.URL.Path) > 18 && r.URL.Path[:18] == "/docs/api/clients/" {
		fmt.Println("[DocsHandler] Serving individual client API")
		h.HandleClientAPI(w, r)
		return
	}

	fmt.Println("[DocsHandler] Path not found, returning 404")
	http.NotFound(w, r)
}

// generateAllApiExplorerSections combines all API explorer flows into one HTML string
func (h *DocsHandler) generateAllApiExplorerSections() string {
	// Combine all major OAuth2 flows for the API Explorer
	return h.generateAuthorizationCodeEndpoints() +
		h.generateClientCredentialsEndpoints() +
		h.generateRefreshTokenEndpoints() +
		h.generateTokenExchangeEndpoints() +
		h.generateDeviceFlowEndpoints()
}

// serveDocs serves the interactive documentation UI using a template
func (h *DocsHandler) serveDocs(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles(
		filepath.Join("templates", "docs.html"),
		filepath.Join("templates", "api_explorer.html"),
		filepath.Join("templates", "client_mgmt.html"),
		filepath.Join("templates", "device_flow.html"),
	)
	if err != nil {
		http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		BaseURL         string
		ApiExplorerHTML template.HTML
		ClientMgmtHTML  template.HTML
		DeviceFlowHTML  template.HTML
	}{
		BaseURL:         h.config.BaseURL,
		ApiExplorerHTML: template.HTML(h.generateAllApiExplorerSections()),
		ClientMgmtHTML:  template.HTML(h.generateClientMgmtEndpoints()),
		DeviceFlowHTML:  template.HTML(h.generateDeviceFlowEndpoints()),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "docs.html", data); err != nil {
		http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
	}
}

// generateDeviceFlowEndpoints creates HTML for device flow endpoints
func (h *DocsHandler) generateDeviceFlowEndpoints() string {
	return `
    <div class="endpoint-card">
      <div class="endpoint-summary">
        <span class="method post">POST</span>
        <span style="margin-right:12px;">/device_authorization</span>
        <span>Device Authorization</span>
      </div>
      <div class="endpoint-details">
        <div style="margin-bottom:10px;">
          <strong>Description:</strong> Start the device authorization flow.
        </div>
        <form class="swagger-form" onsubmit="event.preventDefault(); tryDeviceAuthFlow(this);">
          <div class="form-group">
            <label>client_id</label>
            <input name="client_id" value="frontend-app" required>
          </div>
          <div class="form-group">
            <label>scope</label>
            <input name="scope" value="api:read api:write">
          </div>
          <button type="submit" class="try-btn">Try it out</button>
        </form>
        <div class="request-response" id="deviceauth-response" style="display:none;"></div>
      </div>
    </div>
    <div class="endpoint-card">
      <div class="endpoint-summary">
        <span class="method get">GET</span>
        <span style="margin-right:12px;">/device</span>
        <span>Device Verification</span>
      </div>
      <div class="endpoint-details">
        <div style="margin-bottom:10px;">
          <strong>Description:</strong> Device verification page for users to enter their code.
        </div>
        <div class="test-form">
          <a href="/device" class="btn">Open Device Verification</a>
        </div>
      </div>
    </div>
    <script>
    function tryDeviceAuthFlow(form) {
      var params = new URLSearchParams();
      for (var i = 0; i < form.elements.length; i++) {
        var el = form.elements[i];
        if (el.name && el.value) params.append(el.name, el.value);
      }
      var url = '/device_authorization';
      var curl = 'curl -X POST "' + window.location.origin + url + '" -d "' + params.toString().replace(/&/g, '" -d "') + '"';
      var respDiv = document.getElementById('deviceauth-response');
      respDiv.style.display = 'block';
      respDiv.textContent = 'Request: ' + curl + '\n\n';
      fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params })
        .then(r => r.text())
        .then(txt => { respDiv.textContent += 'Response:\n' + txt; })
        .catch(e => { respDiv.textContent += 'Error: ' + e; });
    }
    </script>
    `
}

func (h *DocsHandler) generateClientMgmtEndpoints() string {
	return `
    <div class="section" style="margin-top: 30px;">
        <div class="section-header">
            <h3>📋 Client Management Dashboard</h3>
        </div>
        <div class="section-content">
            <div id="client-dashboard">
                <div id="client-table-container"></div>
                <div id="client-detail" style="margin-top:30px;"></div>
            </div>
        </div>
    </div>

    <!-- Edit Client Modal -->
    <div id="edit-client-modal" style="display:none;position:fixed;z-index:1000;left:0;top:0;width:100vw;height:100vh;background:rgba(0,0,0,0.4);align-items:center;justify-content:center;">
      <div style="background:white;padding:30px 24px 24px 24px;border-radius:8px;max-width:420px;width:90vw;box-shadow:0 4px 32px rgba(0,0,0,0.2);position:relative;">
        <button onclick="closeEditClientModal()" style="position:absolute;top:10px;right:10px;background:none;border:none;font-size:22px;cursor:pointer;">&times;</button>
        <h3 style="margin-bottom:18px;">Edit Client</h3>
        <form id="edit-client-form">
          <input type="hidden" name="client_id" id="edit-client-id">
          <div class="form-group">
            <label>Name:</label>
            <input name="name" id="edit-client-name" required>
          </div>
          <div class="form-group">
            <label>Description:</label>
            <input name="description" id="edit-client-description">
          </div>
          <div class="form-group">
            <label>Redirect URIs (comma-separated):</label>
            <textarea name="redirect_uris" id="edit-client-redirect-uris"></textarea>
          </div>
          <div class="form-group">
            <label>Grant Types (comma-separated):</label>
            <input name="grant_types" id="edit-client-grant-types">
          </div>
          <div class="form-group">
            <label>Response Types (comma-separated):</label>
            <input name="response_types" id="edit-client-response-types">
          </div>
          <div class="form-group">
            <label>Scopes (comma-separated):</label>
            <input name="scopes" id="edit-client-scopes">
          </div>
          <div class="form-group">
            <label><input type="checkbox" name="public" id="edit-client-public"> Public Client</label>
          </div>
          <div class="form-group">
            <label>Token Endpoint Auth Method:</label>
            <select name="token_endpoint_auth_method" id="edit-client-auth-method">
              <option value="client_secret_basic">client_secret_basic</option>
              <option value="client_secret_post">client_secret_post</option>
              <option value="none">none (for public clients)</option>
            </select>
          </div>
          <button type="submit" class="btn btn-test" style="width:100%;margin-top:10px;">Save Changes</button>
        </form>
        <div id="edit-client-modal-msg" style="margin-top:10px;"></div>
      </div>
    </div>

    <script>
    // Load clients immediately on page load
    document.addEventListener('DOMContentLoaded', function() {
        loadAndRenderClients();
        var form = document.getElementById('edit-client-form');
        if (form) {
            form.onsubmit = function(e) {
                e.preventDefault();
                var clientId = document.getElementById('edit-client-id').value;
                var name = document.getElementById('edit-client-name').value;
                var description = document.getElementById('edit-client-description').value;
                var redirect_uris = document.getElementById('edit-client-redirect-uris').value.split(',').map(s => s.trim()).filter(Boolean);
                var grant_types = document.getElementById('edit-client-grant-types').value.split(',').map(s => s.trim()).filter(Boolean);
                var response_types = document.getElementById('edit-client-response-types').value.split(',').map(s => s.trim()).filter(Boolean);
                var scopes = document.getElementById('edit-client-scopes').value.split(',').map(s => s.trim()).filter(Boolean);
                var isPublic = document.getElementById('edit-client-public').checked;
                var authMethod = document.getElementById('edit-client-auth-method').value;
                var payload = {
                    name: name,
                    description: description,
                    redirect_uris: redirect_uris,
                    grant_types: grant_types,
                    response_types: response_types,
                    scopes: scopes,
                    public: isPublic,
                    token_endpoint_auth_method: authMethod
                };
                fetch('/api/clients/' + encodeURIComponent(clientId), {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                })
                .then(response => {
                    if (response.ok) {
                        document.getElementById('edit-client-modal-msg').innerHTML = '<span style="color:green;">Client updated successfully.</span>';
                        setTimeout(() => {
                            closeEditClientModal();
                            loadAndRenderClients();
                            showClientDetail(clientId);
                        }, 800);
                    } else {
                        return response.text().then(text => { throw new Error(text); });
                    }
                })
                .catch(error => {
                    document.getElementById('edit-client-modal-msg').innerHTML = '<span style="color:red;">Error: ' + error.message + '</span>';
                });
            };
        }
    });

    function loadAndRenderClients() {
        const container = document.getElementById('client-table-container');
        container.innerHTML = '<p>Loading clients...</p>';
        fetch('/api/clients')
            .then(response => response.json())
            .then(clients => {
                if (!Array.isArray(clients) || clients.length === 0) {
                    container.innerHTML = '<p>No clients found.</p>';
                    return;
                }
                let table = '<table class="client-table" style="width:100%;border-collapse:collapse;">';
                table += '<thead><tr>' +
                    '<th style="text-align:left;padding:8px;border-bottom:1px solid #ddd;">Client ID</th>' +
                    '<th style="text-align:left;padding:8px;border-bottom:1px solid #ddd;">Name</th>' +
                    '<th style="text-align:left;padding:8px;border-bottom:1px solid #ddd;">Description</th>' +
                    '<th style="text-align:left;padding:8px;border-bottom:1px solid #ddd;">Grant Types</th>' +
                    '<th style="text-align:left;padding:8px;border-bottom:1px solid #ddd;">Scopes</th>' +
                    '<th style="text-align:left;padding:8px;border-bottom:1px solid #ddd;">Public</th>' +
                    '<th style="text-align:left;padding:8px;border-bottom:1px solid #ddd;">Actions</th>' +
                    '</tr></thead><tbody>';
                clients.forEach(client => {
                    table += '<tr onclick="showClientDetail(\'' + client.id + '\')" style="cursor:pointer;">' +
                        '<td style="padding:8px;border-bottom:1px solid #eee;">' + client.id + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #eee;">' + (client.name || '') + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #eee;">' + (client.description || '') + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #eee;">' + (client.grant_types || []).join(', ') + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #eee;">' + (client.scopes || []).join(', ') + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #eee;">' + (client.public ? 'Yes' : 'No') + '</td>' +
                        '<td style="padding:8px;border-bottom:1px solid #eee;">' +
                            '<button onclick="event.stopPropagation();editClient(\'' + client.id + '\')" class="btn btn-test">' +
                                '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="vertical-align:middle;margin-right:4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16.862 3.487a2.25 2.25 0 1 1 3.182 3.182L7.5 19.213l-4 1 1-4 12.362-12.726z"/></svg>' +
                                'Edit' +
                            '</button>' +
                            '<button onclick="event.stopPropagation();deleteClientFromTable(\'' + client.id + '\')" class="btn" style="background:#dc3545;margin-left:5px;">' +
                                '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="vertical-align:middle;margin-right:4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 7h12M9 7V5a3 3 0 0 1 6 0v2m2 0v12a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V7h12z"/></svg>' +
                                'Delete' +
                            '</button>' +
                        '</td>' +
                    '</tr>';
                });
                table += '</tbody></table>';
                container.innerHTML = table;
            })
            .catch(error => {
                container.innerHTML = '<p style="color: red;">Error loading clients: ' + error.message + '</p>';
            });
    }

    function showClientDetail(clientId) {
        const detail = document.getElementById('client-detail');
        detail.innerHTML = '<p>Loading client details...</p>';
        fetch('/api/clients/' + encodeURIComponent(clientId))
            .then(response => response.json())
            .then(client => {
                let html = '<div class="card" style="max-width:600px;">';
                html += '<h4>' + (client.name || client.id) + '</h4>';
                html += '<p><strong>ID:</strong> ' + client.id + '</p>';
                html += '<p><strong>Description:</strong> ' + (client.description || 'No description') + '</p>';
                html += '<p><strong>Grant Types:</strong> ' + (client.grant_types || []).join(', ') + '</p>';
                html += '<p><strong>Scopes:</strong> ' + (client.scopes || []).join(', ') + '</p>';
                html += '<p><strong>Public:</strong> ' + (client.public ? 'Yes' : 'No') + '</p>';
                html += '<p><strong>Redirect URIs (config):</strong> ' + (client.redirect_uris || []).join(', ') + '</p>';
                html += '<div style="margin-top: 15px;">' +
                    '<button onclick="editClient(\'' + client.id + '\')" class="btn" style="margin-right: 10px;">' +
                        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="vertical-align:middle;margin-right:4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16.862 3.487a2.25 2.25 0 1 1 3.182 3.182L7.5 19.213l-4 1 1-4 12.362-12.726z"/></svg>' +
                    '</button>' +
                    '<button onclick="deleteClientFromTable(\'' + client.id + '\')" class="btn" style="background: #dc3545;">' +
                        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="vertical-align:middle;margin-right:4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 7h12M9 7V5a3 3 0 0 1 6 0v2m2 0v12a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V7h12z"/></svg>' +
                    '</button>' +
                    '</div>';
                html += '</div>';
                detail.innerHTML = html;
            })
            .catch(error => {
                detail.innerHTML = '<p style="color: red;">Error loading client details: ' + error.message + '</p>';
            });
    }

    function editClient(clientId) {
      fetch('/api/clients/' + encodeURIComponent(clientId))
        .then(response => response.json())
        .then(client => {
          document.getElementById('edit-client-id').value = client.id;
          document.getElementById('edit-client-name').value = client.name || '';
          document.getElementById('edit-client-description').value = client.description || '';
          document.getElementById('edit-client-redirect-uris').value = (client.redirect_uris || []).join(', ');
          document.getElementById('edit-client-grant-types').value = (client.grant_types || []).join(', ');
          document.getElementById('edit-client-response-types').value = (client.response_types || []).join(', ');
          document.getElementById('edit-client-scopes').value = (client.scopes || []).join(', ');
          document.getElementById('edit-client-public').checked = !!client.public;
          document.getElementById('edit-client-auth-method').value = client.token_endpoint_auth_method || 'client_secret_basic';
          document.getElementById('edit-client-modal').style.display = 'flex';
          document.getElementById('edit-client-modal-msg').innerHTML = '';
        })
        .catch(error => {
          alert('Error loading client for edit: ' + error.message);
        });
    }

    function closeEditClientModal() {
      document.getElementById('edit-client-modal').style.display = 'none';
    }

    function deleteClientFromTable(clientId) {
        if (confirm('Are you sure you want to delete client "' + clientId + '"? This action cannot be undone.')) {
            fetch('/api/clients/' + encodeURIComponent(clientId), {
                method: 'DELETE'
            })
            .then(response => {
                if (response.status === 204) {
                    alert('Client deleted successfully');
                    // Always clear details and refresh list
                    document.getElementById('client-detail').innerHTML = '';
                    loadAndRenderClients();
                } else {
                    throw new Error('Failed to delete client');
                }
            })
            .catch(error => {
                alert('Error deleting client: ' + error.message);
            });
        }
    }
    </script>
    `
}

// serveOpenAPISpec serves an OpenAPI specification
func (h *DocsHandler) serveOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "OAuth2 Authorization Server",
			"description": "A comprehensive OAuth2 and OpenID Connect server implementation",
			"version":     "1.0.0",
		},
		"servers": []map[string]interface{}{
			{"url": h.config.BaseURL, "description": "OAuth2 Server"},
		},
		"paths": map[string]interface{}{
			"/auth": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Authorization Endpoint",
					"description": "OAuth2 authorization endpoint for initiating authorization code flow",
					"parameters": []map[string]interface{}{
						{
							"name":        "response_type",
							"in":          "query",
							"required":    true,
							"description": "Response type (code, token, id_token)",
							"schema":      map[string]string{"type": "string"},
						},
						{
							"name":        "client_id",
							"in":          "query",
							"required":    true,
							"description": "Client identifier",
							"schema":      map[string]string{"type": "string"},
						},
						{
							"name":        "redirect_uri",
							"in":          "query",
							"required":    false,
							"description": "Redirect URI",
							"schema":      map[string]string{"type": "string"},
						},
						{
							"name":        "scope",
							"in":          "query",
							"required":    false,
							"description": "Requested scope",
							"schema":      map[string]string{"type": "string"},
						},
						{
							"name":        "state",
							"in":          "query",
							"required":    true,
							"description": "State parameter",
							"schema":      map[string]string{"type": "string"},
						},
					},
				},
			},
			"/token": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Token Endpoint",
					"description": "OAuth2 token endpoint for exchanging authorization codes for tokens",
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(spec)
}

// HandleClientsAPI handles the clients list API endpoint
func (h *DocsHandler) HandleClientsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.listClients(w, r)
	case "POST":
		h.createClient(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleClientAPI handles individual client API endpoints
func (h *DocsHandler) HandleClientAPI(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Path[13:] // Remove "/api/clients/" prefix

	switch r.Method {
	case "GET":
		h.getClient(w, r, clientID)
	case "PUT":
		h.updateClient(w, r, clientID)
	case "DELETE":
		h.deleteClient(w, r, clientID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// listClients returns all registered clients
func (h *DocsHandler) listClients(w http.ResponseWriter, r *http.Request) {
	clients := h.clientStore.ListClients()

	var clientList []map[string]interface{}
	for _, client := range clients {
		if storeClient, ok := client.(*store.Client); ok {
			clientInfo := map[string]interface{}{
				"id":                         storeClient.GetID(),
				"name":                       storeClient.Name,
				"description":                storeClient.Description,
				"redirect_uris":              storeClient.GetRedirectURIs(),
				"grant_types":                storeClient.GetGrantTypes(),
				"response_types":             storeClient.GetResponseTypes(),
				"scopes":                     storeClient.GetScopes(),
				"audience":                   storeClient.GetAudience(),
				"token_endpoint_auth_method": storeClient.TokenEndpointAuthMethod,
				"public":                     storeClient.IsPublic(),
				"enabled_flows":              storeClient.EnabledFlows,
			}
			clientList = append(clientList, clientInfo)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clientList)
}

// getClient returns a specific client's details
func (h *DocsHandler) getClient(w http.ResponseWriter, r *http.Request, clientID string) {
	client, err := h.clientStore.GetClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	if storeClient, ok := client.(*store.Client); ok {
		clientInfo := map[string]interface{}{
			"id":                         storeClient.GetID(),
			"name":                       storeClient.Name,
			"description":                storeClient.Description,
			"redirect_uris":              storeClient.GetRedirectURIs(),
			"grant_types":                storeClient.GetGrantTypes(),
			"response_types":             storeClient.GetResponseTypes(),
			"scopes":                     storeClient.GetScopes(),
			"audience":                   storeClient.GetAudience(),
			"token_endpoint_auth_method": storeClient.TokenEndpointAuthMethod,
			"public":                     storeClient.IsPublic(),
			"enabled_flows":              storeClient.EnabledFlows,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(clientInfo)
		return
	}

	http.Error(w, "Invalid client type", http.StatusInternalServerError)
}

// createClient creates a new client
func (h *DocsHandler) createClient(w http.ResponseWriter, r *http.Request) {
	var clientData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&clientData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	name, ok := clientData["name"].(string)
	if !ok || name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Generate client ID and secret
	clientID := fmt.Sprintf("client_%d", len(h.clientStore.ListClients())+1)
	clientSecret := fmt.Sprintf("secret_%d", len(h.clientStore.ListClients())+1)

	// Extract arrays safely
	var redirectURIs []string
	if uris, ok := clientData["redirect_uris"].([]interface{}); ok {
		for _, uri := range uris {
			if uriStr, ok := uri.(string); ok {
				redirectURIs = append(redirectURIs, uriStr)
			}
		}
	}

	var grantTypes []string
	if grants, ok := clientData["grant_types"].([]interface{}); ok {
		for _, grant := range grants {
			if grantStr, ok := grant.(string); ok {
				grantTypes = append(grantTypes, grantStr)
			}
		}
	}
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	var responseTypes []string
	if responses, ok := clientData["response_types"].([]interface{}); ok {
		for _, response := range responses {
			if responseStr, ok := response.(string); ok {
				responseTypes = append(responseTypes, responseStr)
			}
		}
	}
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	var scopes []string
	if clientScopes, ok := clientData["scopes"].([]interface{}); ok {
		for _, scope := range clientScopes {
			if scopeStr, ok := scope.(string); ok {
				scopes = append(scopes, scopeStr)
			}
		}
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	// Create the new client
	newClient := &store.Client{
		ID:                      clientID,
		Secret:                  []byte(clientSecret),
		Name:                    name,
		Description:             getStringValue(clientData, "description"),
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scopes:                  scopes,
		Public:                  getBoolValue(clientData, "public"),
		TokenEndpointAuthMethod: getStringValue(clientData, "token_endpoint_auth_method"),
	}

	if newClient.TokenEndpointAuthMethod == "" {
		newClient.TokenEndpointAuthMethod = "client_secret_basic"
	}

	err := h.clientStore.StoreClient(newClient)
	if err != nil {
		http.Error(w, "Failed to store client", http.StatusInternalServerError)
		return
	}

	// Return the created client with credentials
	response := map[string]interface{}{
		"id":                         newClient.GetID(),
		"secret":                     string(newClient.Secret),
		"name":                       newClient.Name,
		"description":                newClient.Description,
		"redirect_uris":              newClient.GetRedirectURIs(),
		"grant_types":                newClient.GetGrantTypes(),
		"response_types":             newClient.GetResponseTypes(),
		"scopes":                     newClient.GetScopes(),
		"audience":                   newClient.GetAudience(),
		"token_endpoint_auth_method": newClient.TokenEndpointAuthMethod,
		"public":                     newClient.IsPublic(),
		"enabled_flows":              newClient.EnabledFlows,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// updateClient updates an existing client
func (h *DocsHandler) updateClient(w http.ResponseWriter, r *http.Request, clientID string) {
	// Check if client exists
	existingClient, err := h.clientStore.GetClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get the existing client as our base
	storeClient, ok := existingClient.(*store.Client)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Update fields if provided
	if name, ok := updateData["name"].(string); ok && name != "" {
		storeClient.Name = name
	}

	if description, ok := updateData["description"].(string); ok {
		storeClient.Description = description
	}

	// Update arrays if provided
	if uris, ok := updateData["redirect_uris"].([]interface{}); ok {
		var redirectURIs []string
		for _, uri := range uris {
			if uriStr, ok := uri.(string); ok {
				redirectURIs = append(redirectURIs, uriStr)
			}
		}
		storeClient.RedirectURIs = redirectURIs
	}

	if grants, ok := updateData["grant_types"].([]interface{}); ok {
		var grantTypes []string
		for _, grant := range grants {
			if grantStr, ok := grant.(string); ok {
				grantTypes = append(grantTypes, grantStr)
			}
		}
		storeClient.GrantTypes = grantTypes
	}

	if responses, ok := updateData["response_types"].([]interface{}); ok {
		var responseTypes []string
		for _, response := range responses {
			if responseStr, ok := response.(string); ok {
				responseTypes = append(responseTypes, responseStr)
			}
		}
		storeClient.ResponseTypes = responseTypes
	}

	if clientScopes, ok := updateData["scopes"].([]interface{}); ok {
		var scopes []string
		for _, scope := range clientScopes {
			if scopeStr, ok := scope.(string); ok {
				scopes = append(scopes, scopeStr)
			}
		}
		storeClient.Scopes = scopes
	}

	if public, ok := updateData["public"].(bool); ok {
		storeClient.Public = public
	}

	if authMethod, ok := updateData["token_endpoint_auth_method"].(string); ok && authMethod != "" {
		storeClient.TokenEndpointAuthMethod = authMethod
	}

	// Store the updated client
	err = h.clientStore.StoreClient(storeClient)
	if err != nil {
		http.Error(w, "Failed to update client", http.StatusInternalServerError)
		return
	}

	// Return the updated client
	response := map[string]interface{}{
		"id":                         storeClient.GetID(),
		"name":                       storeClient.Name,
		"description":                storeClient.Description,
		"redirect_uris":              storeClient.GetRedirectURIs(),
		"grant_types":                storeClient.GetGrantTypes(),
		"response_types":             storeClient.GetResponseTypes(),
		"scopes":                     storeClient.GetScopes(),
		"audience":                   storeClient.GetAudience(),
		"token_endpoint_auth_method": storeClient.TokenEndpointAuthMethod,
		"public":                     storeClient.IsPublic(),
		"enabled_flows":              storeClient.EnabledFlows,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// deleteClient deletes a client
func (h *DocsHandler) deleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	err := h.clientStore.DeleteClient(clientID)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Helper functions
func getStringValue(data map[string]interface{}, key string) string {
	if value, ok := data[key].(string); ok {
		return value
	}
	return ""
}

func getBoolValue(data map[string]interface{}, key string) bool {
	if value, ok := data[key].(bool); ok {
		return value
	}
	return false
}
