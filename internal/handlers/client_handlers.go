package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
)

// ClientHandler provides HTTP handlers for client management
type ClientHandler struct {
	clientStore *store.ClientStore
	config      *config.Config
}

// escapeAndJoin safely joins a slice of strings for HTML output
func escapeAndJoin(arr []string) string {
	if len(arr) == 0 {
		return "<em>None</em>"
	}
	s := ""
	for i, v := range arr {
		if i > 0 {
			s += ", "
		}
		s += htmlEscape(v)
	}
	return s
}

// htmlEscape escapes special HTML characters
func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

// NewClientHandler creates a new ClientHandler
func NewClientHandler(clientStore *store.ClientStore, config *config.Config) *ClientHandler {
	return &ClientHandler{
		clientStore: clientStore,
		config:      config,
	}
}

// Helper to get first element or empty string
func firstOrEmpty(arr []string) string {
	if len(arr) > 0 {
		return arr[0]
	}
	return ""
}

// HandleClients lists all configured clients
func (h *ClientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("🔍 Debug: Listing all configured clients")

	// Render HTML client list with Edit button
	html := `<html><head><title>Clients</title>
	   <style>
	   body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
	   h2 { color: #333; }
	   table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: #fff; }
	   th, td { padding: 10px 12px; border: 1px solid #ddd; }
	   th { background: #f1f3f4; }
	   tr:nth-child(even) { background: #f9f9f9; }
	   .actions a, .actions button { margin-right: 8px; }
	   .edit-btn { color: #007bff; text-decoration: none; }
	   .edit-btn:hover { text-decoration: underline; }
	   .delete-btn { color: #dc3545; background: none; border: none; cursor: not-allowed; opacity: 0.5; }
	   </style></head><body>`
	html += `<h2>🔑 Configured Clients</h2><table>`
	html += `<tr><th>ID</th><th>Name</th><th>Description</th><th>Redirect URIs</th><th>Grant Types</th><th>Scopes</th><th>Actions</th></tr>`
	for _, clientConfig := range h.config.Clients {
		html += `<tr class="client-row" data-client-id="` + htmlEscape(clientConfig.ID) + `">`
		html += `<td>` + clientConfig.ID + `</td>`
		html += `<td>` + clientConfig.Name + `</td>`
		html += `<td>` + clientConfig.Description + `</td>`
		html += `<td>` + escapeAndJoin(clientConfig.RedirectURIs) + `</td>`
		html += `<td>` + escapeAndJoin(clientConfig.GrantTypes) + `</td>`
		html += `<td>` + escapeAndJoin(clientConfig.Scopes) + `</td>`
		html += `<td class="actions">
		 <button class="edit-btn" data-client-id="` + htmlEscape(clientConfig.ID) + `">Edit</button>
		 <button class="delete-btn" disabled title="Delete not implemented">Delete</button>
	   </td>`
		html += `</tr>`
	}
	html += `</table>`
	html += `<p><a href="/">← Back to Home</a></p>`
	// Modal dialog for editing
	html += `<div id="editModal" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.3);z-index:1000;align-items:center;justify-content:center;">
		 <div style="background:#fff;padding:32px 24px;border-radius:8px;max-width:400px;margin:80px auto;box-shadow:0 2px 16px #0002;position:relative;">
		   <h3>Edit Client</h3>
		   <form id="editForm">
			 <input type="hidden" name="client_id" id="edit_client_id">
			 <label>Name:</label><br>
			 <input type="text" name="name" id="edit_name"><br><br>
			 <label>Description:</label><br>
			 <input type="text" name="description" id="edit_description"><br><br>
			 <label>Redirect URI:</label><br>
			 <input type="text" name="redirect_uri" id="edit_redirect_uri"><br><br>
			 <label>Grant Type:</label><br>
			 <input type="text" name="grant_type" id="edit_grant_type"><br><br>
			 <label>Scope:</label><br>
			 <input type="text" name="scope" id="edit_scope"><br><br>
			 <button type="submit" id="edit_save_btn">Save</button>
			 <button type="button" onclick="closeEditModal()">Cancel</button>
		   </form>
		   <div id="edit_feedback" style="margin-top:12px;font-size:15px;"></div>
		   <span style="position:absolute;top:8px;right:12px;cursor:pointer;font-size:20px;" onclick="closeEditModal()" aria-label="Close">&times;</span>
		 </div>
	   </div>`
	html += `<script>
	   // Master-detail: click row to open modal and fetch details
	   document.addEventListener('DOMContentLoaded', function() {
		 // Row click still opens modal
		 document.querySelectorAll('.client-row').forEach(function(row) {
		   row.addEventListener('click', function(e) {
			 // Only trigger if not clicking the Edit button
			 if (e.target.classList.contains('edit-btn')) return;
			 const clientId = this.getAttribute('data-client-id');
			 openEditModalForClient(clientId);
		   });
		 });
		 // Edit button click opens modal
		 document.querySelectorAll('.edit-btn').forEach(function(btn) {
		   btn.addEventListener('click', function(e) {
			 e.stopPropagation();
			 const clientId = this.getAttribute('data-client-id');
			 openEditModalForClient(clientId);
		   });
		 });
	   });
	   async function openEditModalForClient(clientId) {
		 try {
		   const resp = await fetch('/admin/client?client_id=' + encodeURIComponent(clientId));
		   if (!resp.ok) throw new Error('Failed to fetch client details');
		   const data = await resp.json();
		   document.getElementById('edit_client_id').value = data.client_id;
		   document.getElementById('edit_name').value = data.name || '';
		   document.getElementById('edit_description').value = data.description || '';
		   document.getElementById('edit_redirect_uri').value = (data.redirect_uris && data.redirect_uris[0]) || '';
		   document.getElementById('edit_grant_type').value = (data.grant_types && data.grant_types[0]) || '';
		   document.getElementById('edit_scope').value = (data.scopes && data.scopes[0]) || '';
		   document.getElementById('edit_feedback').textContent = '';
		   document.getElementById('edit_save_btn').disabled = false;
		   document.getElementById('editModal').style.display = 'flex';
		   setTimeout(function() { document.getElementById('edit_name').focus(); }, 100);
		 } catch (err) {
		   alert('Could not load client details: ' + err.message);
		 }
	   }
	   function closeEditModal() {
		 document.getElementById('editModal').style.display = 'none';
		 document.getElementById('edit_feedback').textContent = '';
	   }
	   document.getElementById('editForm').onsubmit = async function(e) {
		 e.preventDefault();
		 // Field validation
		 const name = this.name.value.trim();
		 const redirect = this.redirect_uri.value.trim();
		 const grant = this.grant_type.value.trim();
		 let error = '';
		 if (!name) error = 'Name is required.';
		 else if (!redirect) error = 'Redirect URI is required.';
		 else if (!grant) error = 'Grant type is required.';
		 else if (redirect && !/^https?:\/\/.+/.test(redirect)) error = 'Redirect URI must start with http:// or https://';
		 if (error) {
		   document.getElementById('edit_feedback').textContent = error;
		   document.getElementById('edit_save_btn').disabled = false;
		   return;
		 }
		 document.getElementById('edit_save_btn').disabled = true;
		 document.getElementById('edit_feedback').textContent = 'Saving...';
		 const data = {
		   client_id: this.client_id.value,
		   name: name,
		   description: this.description.value,
		   redirect_uri: redirect,
		   grant_type: grant,
		   scope: this.scope.value
		 };
		 try {
		   const resp = await fetch('/admin/client', {
			 method: 'POST',
			 headers: { 'Content-Type': 'application/json' },
			 body: JSON.stringify(data)
		   });
		   if (resp.ok) {
			 document.getElementById('edit_feedback').textContent = 'Saved!';
			 setTimeout(function() {
			   closeEditModal();
			   window.location.reload();
			 }, 700);
		   } else {
			 let msg = 'Failed to update client';
			 try { msg = (await resp.json()).message || msg; } catch {}
			 document.getElementById('edit_feedback').textContent = msg;
			 document.getElementById('edit_save_btn').disabled = false;
		   }
		 } catch (err) {
		   document.getElementById('edit_feedback').textContent = 'Network error';
		   document.getElementById('edit_save_btn').disabled = false;
		 }
	   };
	   </script>`
	html += `</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
	log.Printf("✅ Debug: Listed %d clients", len(h.config.Clients))

}

// HandleClient shows details for a specific client
func (h *ClientHandler) HandleClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id parameter is required", http.StatusBadRequest)
		return
	}

	log.Printf("🔍 Debug: Looking up client: %s", clientID)

	// Check if client exists in config
	var foundClient *config.ClientConfig
	for _, client := range h.config.Clients {
		if client.ID == clientID {
			foundClient = &client
			break
		}
	}

	if foundClient == nil {
		response := map[string]interface{}{
			"error":       "client_not_found",
			"message":     "Client not found in configuration",
			"client_id":   clientID,
			"searched_in": "config.yaml",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if client exists in store
	storeClient, err := h.clientStore.GetClient(r.Context(), clientID)
	var storeExists bool
	var storeError string
	if err != nil {
		storeError = err.Error()
		storeExists = false
	} else {
		storeExists = storeClient != nil
	}

	response := map[string]interface{}{
		"client_id":                  foundClient.ID,
		"name":                       foundClient.Name,
		"description":                foundClient.Description,
		"redirect_uris":              foundClient.RedirectURIs,
		"grant_types":                foundClient.GrantTypes,
		"response_types":             foundClient.ResponseTypes,
		"scopes":                     foundClient.Scopes,
		"audience":                   foundClient.Audience,
		"token_endpoint_auth_method": foundClient.TokenEndpointAuthMethod,
		"public":                     foundClient.Public,
		"enabled_flows":              foundClient.EnabledFlows,
		"has_secret":                 foundClient.Secret != "",
		"config_status": map[string]interface{}{
			"found_in_config": true,
			"found_in_store":  storeExists,
			"store_error":     storeError,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Debug: Client %s found in config, store_exists=%t", clientID, storeExists)
}

// HandleClientConfig shows current configuration
func (h *ClientHandler) HandleClientConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("🔍 Debug: Showing current configuration")

	response := map[string]interface{}{
		"server": map[string]interface{}{
			"base_url":         h.config.Server.BaseURL,
			"port":             h.config.Server.Port,
			"host":             h.config.Server.Host,
			"read_timeout":     h.config.Server.ReadTimeout,
			"write_timeout":    h.config.Server.WriteTimeout,
			"shutdown_timeout": h.config.Server.ShutdownTimeout,
		},
		"security": map[string]interface{}{
			"token_expiry_seconds":         h.config.Security.TokenExpirySeconds,
			"refresh_token_expiry_seconds": h.config.Security.RefreshTokenExpirySeconds,
			"device_code_expiry_seconds":   h.config.Security.DeviceCodeExpirySeconds,
			"enable_pkce":                  h.config.Security.EnablePKCE,
			"require_https":                h.config.Security.RequireHTTPS,
			"has_jwt_secret":               h.config.Security.JWTSecret != "",
		},
		"clients_count": len(h.config.Clients),
		"users_count":   len(h.config.Users),
		"logging": map[string]interface{}{
			"level":        h.config.Logging.Level,
			"format":       h.config.Logging.Format,
			"enable_audit": h.config.Logging.EnableAudit,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("✅ Debug: Configuration displayed")
}

// HandleEditClient displays and processes the edit form for a client
func (h *ClientHandler) HandleEditClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id parameter is required", http.StatusBadRequest)
		return
	}

	// Find client in config
	var foundClient *config.ClientConfig
	for i, client := range h.config.Clients {
		if client.ID == clientID {
			foundClient = &h.config.Clients[i]
			break
		}
	}
	if foundClient == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	if r.Method == "POST" {
		// Process form submission
		r.ParseForm()
		foundClient.Name = r.FormValue("name")
		foundClient.Description = r.FormValue("description")
		foundClient.RedirectURIs = []string{r.FormValue("redirect_uri")}
		foundClient.GrantTypes = []string{r.FormValue("grant_type")}
		foundClient.Scopes = []string{r.FormValue("scope")}
		// You can expand this to handle more fields as needed

		// TODO: Persist changes to config.yaml if needed

		http.Redirect(w, r, "/debug/clients", http.StatusSeeOther)
		return
	}

	// Show edit form with JS POST
	html := `<html><head><title>Edit Client</title></head><body>
	<h2>Edit Client: ` + foundClient.ID + `</h2>
	<form id="editForm">
		<label>Name:</label><br>
		<input type="text" name="name" value="` + foundClient.Name + `"><br><br>
		<label>Description:</label><br>
		<input type="text" name="description" value="` + foundClient.Description + `"><br><br>
		<label>Redirect URI:</label><br>
		<input type="text" name="redirect_uri" value="` + firstOrEmpty(foundClient.RedirectURIs) + `"><br><br>
		<label>Grant Type:</label><br>
		<input type="text" name="grant_type" value="` + firstOrEmpty(foundClient.GrantTypes) + `"><br><br>
		<label>Scope:</label><br>
		<input type="text" name="scope" value="` + firstOrEmpty(foundClient.Scopes) + `"><br><br>
		<button type="submit">Save</button>
		<a href="/debug/clients">Cancel</a>
	</form>
	<script>
	document.getElementById('editForm').onsubmit = async function(e) {
		e.preventDefault();
		const data = {
			client_id: '` + foundClient.ID + `',
			name: this.name.value,
			description: this.description.value,
			redirect_uri: this.redirect_uri.value,
			grant_type: this.grant_type.value,
			scope: this.scope.value
		};
		const resp = await fetch('/admin/client', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(data)
		});
		if (resp.ok) {
			window.location.href = '/debug/clients';
		} else {
			alert('Failed to update client');
		}
	};
	</script>
	</body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// HandleClientUpdate processes POST API to update client details
func (h *ClientHandler) HandleClientUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ClientID    string `json:"client_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		RedirectURI string `json:"redirect_uri"`
		GrantType   string `json:"grant_type"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	// Find client
	var foundClient *config.ClientConfig
	for i, client := range h.config.Clients {
		if client.ID == req.ClientID {
			foundClient = &h.config.Clients[i]
			break
		}
	}
	if foundClient == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}
	// Update fields
	foundClient.Name = req.Name
	foundClient.Description = req.Description
	foundClient.RedirectURIs = []string{req.RedirectURI}
	foundClient.GrantTypes = []string{req.GrantType}
	foundClient.Scopes = []string{req.Scope}
	// TODO: Persist changes to config.yaml if needed
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"updated"}`))
}
