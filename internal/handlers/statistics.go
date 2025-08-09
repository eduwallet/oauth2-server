package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
)

// StatsHandler handles statistics requests
type StatsHandler struct {
	ClientManager *store.ClientManager // ← Updated from ClientStore
	Config        *config.Config
}

// ServeHTTP implements http.Handler (updated for struct return)
func (h *StatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get client count directly from the manager
	clientCount := h.ClientManager.GetClientCount()

	stats := map[string]interface{}{
		"clients": map[string]interface{}{
			"total": clientCount,
		},
		"server": map[string]interface{}{
			"version": "1.0.0", // You could pull this from config
			"status":  "running",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// The getClientCount method has been removed as it was redundant.
