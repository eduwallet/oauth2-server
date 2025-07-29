package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
)

// DocsHandler provides interactive API documentation
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

// serveDocs serves the interactive documentation UI
func (h *DocsHandler) serveDocs(w http.ResponseWriter, r *http.Request) {
    html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth2 Server API Documentation</title>
    <style>
        body {
            font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
            background: #f7f8fa;
            margin: 0;
            color: #222;
        }
        .container {
            max-width: 900px;
            margin: 40px auto 40px auto;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 4px 32px rgba(0,0,0,0.08);
            padding: 32px 32px 40px 32px;
        }
        .header {
            border-bottom: 1px solid #e5e7eb;
            margin-bottom: 24px;
            padding-bottom: 12px;
        }
        .header h1 {
            margin: 0 0 8px 0;
            font-size: 2.2rem;
            font-weight: 700;
            color: #2d3748;
        }
        .header p {
            margin: 0;
            color: #4a5568;
        }
        .nav {
            margin: 24px 0 24px 0;
        }
        .nav-links {
            display: flex;
            gap: 18px;
        }
        .nav-link {
            color: #2563eb;
            text-decoration: none;
            font-weight: 500;
            padding: 6px 14px;
            border-radius: 6px;
            transition: background 0.15s;
        }
        .nav-link:hover {
            background: #e0e7ff;
        }
        .section {
            margin-top: 32px;
        }
        .section-header h2, .section-header h3 {
            margin: 0 0 10px 0;
            font-size: 1.3rem;
            color: #1a202c;
            font-weight: 600;
        }
        .section-content {
            margin-left: 8px;
        }
        .endpoint {
            background: #f8fafc;
            border-radius: 8px;
            margin-bottom: 22px;
            padding: 0;
            box-shadow: 0 1px 4px rgba(0,0,0,0.03);
            border-left: 6px solid #2563eb;
            overflow: hidden;
        }
        .endpoint .endpoint-header {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.08rem;
            background: #e0e7ff;
            padding: 12px 20px 10px 20px;
            border-bottom: 1px solid #e5e7eb;
        }
        .endpoint .method {
            font-size: 0.98rem;
            font-weight: 700;
            padding: 2px 14px;
            border-radius: 5px;
            color: #fff;
            margin-right: 10px;
            font-family: 'Fira Mono', 'Menlo', 'Consolas', monospace;
            letter-spacing: 0.5px;
        }
        .endpoint .method.get { background: #2563eb; }
        .endpoint .method.post { background: #059669; }
        .endpoint .method.delete { background: #dc2626; }
        .endpoint .method.put { background: #f59e42; }
        .endpoint .path {
            font-family: 'Fira Mono', 'Menlo', 'Consolas', monospace;
            font-size: 1.08rem;
            color: #22223b;
            background: #f3f4f6;
            padding: 2px 10px;
            border-radius: 4px;
            margin-right: 10px;
        }
        .endpoint .summary {
            font-weight: 500;
            color: #374151;
            font-size: 1.01rem;
        }
        .endpoint-details {
            padding: 18px 22px 12px 22px;
        }
        .endpoint-details p {
            margin: 0 0 10px 0;
            color: #374151;
            font-size: 0.98rem;
        }
        .test-form {
            margin-top: 8px;
        }
        .form-group {
            margin-bottom: 10px;
        }
        .form-group label {
            display: block;
            font-size: 0.98rem;
            color: #374151;
            margin-bottom: 2px;
        }
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 7px 10px;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            font-size: 1rem;
            background: #fff;
            margin-bottom: 2px;
        }
        .form-group textarea {
            min-height: 38px;
            resize: vertical;
        }
        .btn {
            background: #2563eb;
            color: #fff;
            border: none;
            border-radius: 5px;
            padding: 7px 18px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.15s;
        }
        .btn:hover {
            background: #1d4ed8;
        }
        .btn-test {
            background: #059669;
        }
        .btn-test:hover {
            background: #047857;
        }
        .client-table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 10px;
        }
        .client-table th, .client-table td {
            border-bottom: 1px solid #e5e7eb;
            padding: 8px 10px;
            text-align: left;
        }
        .client-table th {
            background: #f3f4f6;
            font-weight: 600;
        }
        .client-table tr:hover {
            background: #e0e7ff;
        }
        .card {
            background: #f9fafb;
            border-radius: 8px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.04);
            padding: 18px 20px;
            margin-bottom: 12px;
        }
        #edit-client-modal {
            display: none;
            align-items: center;
            justify-content: center;
        }
        #edit-client-modal[style*="display:flex"] {
            display: flex !important;
        }
        @media (max-width: 600px) {
            .container {
                padding: 10px 2vw 20px 2vw;
            }
            .header h1 {
                font-size: 1.3rem;
            }
            .section-header h2, .section-header h3 {
                font-size: 1.05rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>OAuth2 Server API Documentation</h1>
            <p>Modern OAuth2 and OpenID Connect server with interactive API docs and client dashboard.</p>
        </div>
        <div class="nav">
            <div class="nav-links">
                <a href="%s/docs" class="nav-link">API Docs</a>
                <a href="%s/health" class="nav-link">Health</a>
                <a href="%s/.well-known/oauth-authorization-server" class="nav-link">Discovery</a>
            </div>
        </div>
        <div class="section">
            <div class="section-header"><h2>Authorization & User Info</h2></div>
            <div class="section-content">
                %s
            </div>
        </div>
        <div class="section">
            <div class="section-header"><h2>Token Endpoints</h2></div>
            <div class="section-content">
                %s
            </div>
        </div>
        <div class="section">
            <div class="section-header"><h2>Device Flow</h2></div>
            <div class="section-content">
                %s
            </div>
        </div>
        %s
    </div>
</body>
</html>`,
        h.config.BaseURL,
        h.config.BaseURL,
        h.config.BaseURL,
        h.generateAuthEndpoints(),
        h.generateTokenEndpoints(),
        h.generateDeviceFlowEndpoints(),
        h.generateClientMgmtEndpoints(),
    )

    fmt.Printf("[DocsHandler] serveDocs HTML preview: %s\n", html[:200])
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.Write([]byte(html))
}

// generateAuthEndpoints creates HTML for authentication endpoints
func (h *DocsHandler) generateAuthEndpoints() string {
    return `
        <div class="endpoint">
            <div class="endpoint-header">
                <span class="method get">GET</span>
                <span class="path">/auth</span>
                <span class="summary">Authorization Endpoint</span>
            </div>
            <div class="endpoint-details">
                <p><strong>Description:</strong> Initiates the OAuth2 authorization code flow.</p>
                <div class="test-form">
                    <form onsubmit="event.preventDefault(); testEndpoint(this, '/auth', 'GET');">
                        <div class="form-group">
                            <label>Response Type:</label>
                            <select name="response_type">
                                <option value="code">code</option>
                                <option value="token">token</option>
                                <option value="id_token">id_token</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Client ID:</label>
                            <input name="client_id" value="frontend-app" placeholder="frontend-app">
                        </div>
                        <div class="form-group">
                            <label>Redirect URI:</label>
                            <input name="redirect_uri" value="` + h.config.BaseURL + `/client1/callback">
                        </div>
                        <div class="form-group">
                            <label>Scope:</label>
                            <input name="scope" value="openid profile email api:read">
                        </div>
                        <div class="form-group">
                            <label>State:</label>
                            <input name="state" value="xyz123">
                        </div>
                        <button type="submit" class="btn btn-test">Test Authorization</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="endpoint">
            <div class="endpoint-header">
                <span class="method get">GET</span>
                <span class="path">/userinfo</span>
                <span class="summary">User Info Endpoint</span>
            </div>
            <div class="endpoint-details">
                <p><strong>Description:</strong> Returns user information for the authenticated user.</p>
                <div class="test-form">
                    <form onsubmit="event.preventDefault(); testEndpoint(this, '/userinfo', 'GET');">
                        <div class="form-group">
                            <label>Authorization Header:</label>
                            <input name="authorization" placeholder="Bearer YOUR_ACCESS_TOKEN">
                        </div>
                        <button type="submit" class="btn btn-test">Test UserInfo</button>
                    </form>
                </div>
            </div>
        </div>
    `
}

// generateTokenEndpoints creates HTML for token endpoints
func (h *DocsHandler) generateTokenEndpoints() string {
    return `
        <div class="endpoint">
            <div class="endpoint-header">
                <span class="method post">POST</span>
                <span>/token</span>
                <span>Token Endpoint</span>
            </div>
            <div class="endpoint-details">
                <p>Exchange authorization code for access token or handle other token grant types.</p>
                <div class="test-form">
                    <form onsubmit="event.preventDefault(); testEndpoint(this, '/token', 'POST');">
                        <div class="form-group">
                            <label>Grant Type:</label>
                            <select name="grant_type">
                                <option value="authorization_code">authorization_code</option>
                                <option value="client_credentials">client_credentials</option>
                                <option value="refresh_token">refresh_token</option>
                                <option value="urn:ietf:params:oauth:grant-type:device_code">device_code</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Client ID:</label>
                            <input name="client_id" value="frontend-app">
                        </div>
                        <div class="form-group">
                            <label>Client Secret:</label>
                            <input name="client_secret" value="frontend-secret">
                        </div>
                        <div class="form-group">
                            <label>Code (for authorization_code):</label>
                            <input name="code" placeholder="Authorization code from /auth">
                        </div>
                        <div class="form-group">
                            <label>Redirect URI (for authorization_code):</label>
                            <input name="redirect_uri" value="` + h.config.BaseURL + `/client1/callback">
                        </div>
                        <button type="submit" class="btn btn-test">Test Token Request</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="endpoint">
            <div class="endpoint-header">
                <span class="method post">POST</span>
                <span>/introspect</span>
                <span>Token Introspection</span>
            </div>
            <div class="endpoint-details">
                <p>Get information about an access token.</p>
                <div class="test-form">
                    <form onsubmit="event.preventDefault(); testEndpoint(this, '/introspect', 'POST');">
                        <div class="form-group">
                            <label>Token:</label>
                            <input name="token" placeholder="Access token to introspect">
                        </div>
                        <div class="form-group">
                            <label>Client ID:</label>
                            <input name="client_id" value="frontend-app">
                        </div>
                        <div class="form-group">
                            <label>Client Secret:</label>
                            <input name="client_secret" value="frontend-secret">
                        </div>
                        <button type="submit" class="btn btn-test">Test Introspection</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="endpoint">
            <div class="endpoint-header">
                <span class="method post">POST</span>
                <span>/revoke</span>
                <span>Token Revocation</span>
            </div>
            <div class="endpoint-details">
                <p>Revoke an access or refresh token.</p>
                <div class="test-form">
                    <form onsubmit="event.preventDefault(); testEndpoint(this, '/revoke', 'POST');">
                        <div class="form-group">
                            <label>Token:</label>
                            <input name="token" placeholder="Token to revoke">
                        </div>
                        <div class="form-group">
                            <label>Client ID:</label>
                            <input name="client_id" value="frontend-app">
                        </div>
                        <div class="form-group">
                            <label>Client Secret:</label>
                            <input name="client_secret" value="frontend-secret">
                        </div>
                        <button type="submit" class="btn btn-test">Test Revocation</button>
                    </form>
                </div>
            </div>
        </div>
    `
}

// generateDeviceFlowEndpoints creates HTML for device flow endpoints
func (h *DocsHandler) generateDeviceFlowEndpoints() string {
    return `
        <div class="endpoint">
            <div class="endpoint-header">
                <span class="method post">POST</span>
                <span>/device_authorization</span>
                <span>Device Authorization</span>
            </div>
            <div class="endpoint-details">
                <p>Start the device authorization flow.</p>
                <div class="test-form">
                    <form onsubmit="event.preventDefault(); testEndpoint(this, '/device_authorization', 'POST');">
                        <div class="form-group">
                            <label>Client ID:</label>
                            <input name="client_id" value="frontend-app">
                        </div>
                        <div class="form-group">
                            <label>Scope:</label>
                            <input name="scope" value="api:read api:write">
                        </div>
                        <button type="submit" class="btn btn-test">Test Device Authorization</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="endpoint">
            <div class="endpoint-header">
                <span class="method get">GET</span>
                <span>/device</span>
                <span>Device Verification</span>
            </div>
            <div class="endpoint-details">
                <p>Device verification page for users to enter their code.</p>
                <div class="test-form">
                    <a href="/device" class="btn">Open Device Verification</a>
                </div>
            </div>
        </div>
    `
}

func (h *DocsHandler) generateClientMgmtEndpoints() string {
    return `
    <div class="section" style="margin-top: 30px;">
        <div class="section-header">
            <h3>📋 Client Management Dashboard</h3>
        </div>
        <div class="section-content">
            <div style="margin-bottom: 20px;">
                <button onclick="loadClientDashboard()" class="btn btn-test">Load Clients Dashboard</button>
                <button onclick="refreshClientTable()" class="btn" style="margin-left: 10px;">Refresh</button>
            </div>
            <div id="client-dashboard" style="display: none;">
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
    function loadClientDashboard() {
        document.getElementById('client-dashboard').style.display = 'block';
        refreshClientTable();
    }

    function refreshClientTable() {
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
                        'Edit' +
                    '</button>' +
                    '<button onclick="deleteClientFromTable(\'' + client.id + '\')" class="btn" style="background: #dc3545;">' +
                        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="vertical-align:middle;margin-right:4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 7h12M9 7V5a3 3 0 0 1 6 0v2m2 0v12a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V7h12z"/></svg>' +
                        'Delete' +
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

    document.addEventListener('DOMContentLoaded', function() {
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
                if (typeof refreshClientTable === 'function') refreshClientTable();
                if (typeof showClientDetail === 'function') showClientDetail(clientId);
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

    function deleteClientFromTable(clientId) {
        if (confirm('Are you sure you want to delete client "' + clientId + '"? This action cannot be undone.')) {
            fetch('/api/clients/' + encodeURIComponent(clientId), {
                method: 'DELETE'
            })
            .then(response => {
                if (response.status === 204) {
                    alert('Client deleted successfully');
                    refreshClientTable();
                    document.getElementById('client-detail').innerHTML = '';
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
                            "required":    false,
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
