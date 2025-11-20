package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/store"
)

// StatisticsHandler handles statistics requests
type StatisticsHandler struct {
	Storage store.Storage
	Metrics *metrics.MetricsCollector
}

// ServeHTTP implements http.Handler (updated for struct return)
func (h *StatisticsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		if h.Metrics != nil {
			h.Metrics.RecordHTTPRequest(r.Method, "stats", http.StatusMethodNotAllowed, 0)
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get counts from storage (ignore errors for stats)
	accessTokenCount, _ := h.Storage.GetAccessTokenCount()
	clientCount, _ := h.Storage.GetClientCount()
	userCount, _ := h.Storage.GetUserCount()

	stats := map[string]interface{}{
		"server": map[string]interface{}{
			"version": "1.0.0", // You could pull this from config
			"status":  "running",
		},
		"tokens":  accessTokenCount,
		"clients": clientCount,
		"users":   userCount,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
