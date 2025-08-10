package handlers

import (
	"net/http"

	"github.com/ory/fosite/storage"
)

type RegistrationHandler struct {
	memoryStore *storage.MemoryStore
}

func NewRegistrationHandler(memoryStore *storage.MemoryStore) *RegistrationHandler {
	return &RegistrationHandler{
		memoryStore: memoryStore,
	}
}

func (h *RegistrationHandler) HandleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	http.Error(w, "Method not yet implemented", http.StatusMethodNotAllowed)

	// var req storage.ClientRegistrationRequest
	// if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
	// 	http.Error(w, "Invalid JSON", http.StatusBadRequest)
	// 	return
	// }

	// // Register the client
	// client, err := h.clientManager.RegisterClient(req)
	// if err != nil {
	// 	http.Error(w, "Registration failed", http.StatusInternalServerError)
	// 	return
	// }

	// // Return client credentials
	// response := map[string]interface{}{
	// 	"client_id":     client.ID,
	// 	"client_secret": client.Secret,
	// 	"client_name":   client.Name,
	// 	"grant_types":   client.GrantTypes,
	// 	"scopes":        client.Scopes,
	// }

	// w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(response)
}

// HandleClientConfiguration handles client configuration requests (placeholder)
func (h *RegistrationHandler) HandleClientConfiguration(w http.ResponseWriter, r *http.Request) {
	// This is a placeholder for RFC 7592 dynamic client management
	// For now, return method not implemented
	http.Error(w, "Client configuration not implemented", http.StatusNotImplemented)
}
