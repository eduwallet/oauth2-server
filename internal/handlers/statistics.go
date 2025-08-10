package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/ory/fosite/storage"
)

// StatisticsHandler handles statistics requests
type StatisticsHandler struct {
	MemoryStore *storage.MemoryStore
}

// ServeHTTP implements http.Handler (updated for struct return)
func (h *StatisticsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"version": "1.0.0", // You could pull this from config
			"status":  "running",
		},
		"tokens":  len(h.MemoryStore.AccessTokens),
		"clients": len(h.MemoryStore.Clients),
		"users":   len(h.MemoryStore.Users),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
