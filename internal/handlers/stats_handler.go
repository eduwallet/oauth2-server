package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
)

type StatsHandler struct {
	TokenStore  *store.TokenStore
	ClientStore *store.ClientStore
	Config      *config.Config
}

func (h *StatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"tokens":  h.TokenStore.GetStats(),
		"clients": h.ClientStore.GetStats(), // Implement GetStats for ClientStore
		"users":   len(h.Config.Users),      // Or more detailed user stats if needed
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
