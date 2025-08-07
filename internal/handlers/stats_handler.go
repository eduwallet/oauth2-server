package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
)

// StatsHandler handles statistics requests
type StatsHandler struct {
	TokenStore    *store.TokenStore
	ClientManager *store.SimpleClientManager // ← Updated from ClientStore
	Config        *config.Config
}

// ServeHTTP implements http.Handler (updated for struct return)
func (h *StatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token statistics (now returns *TokenStats)
	tokenStats := h.TokenStore.GetStats()

	// Get client count
	clientCount := h.getClientCount()

	stats := map[string]interface{}{
		"tokens": map[string]interface{}{
			"total":     tokenStats.Total,
			"active":    tokenStats.Active,
			"expired":   tokenStats.Expired,
			"revoked":   tokenStats.Revoked,
			"by_type":   tokenStats.ByType,
			"by_client": tokenStats.ByClient,
		},
		"clients": map[string]interface{}{
			"total": clientCount,
		},
		"server": map[string]interface{}{
			"version": "1.0.0",
			"status":  "running",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// getClientCount returns the number of registered clients
func (h *StatsHandler) getClientCount() int {
	return h.ClientManager.GetClientCount() // ← Use the implemented method
}
