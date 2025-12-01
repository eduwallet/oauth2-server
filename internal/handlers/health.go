package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"time"
)

// HealthHandler manages health check requests
type HealthHandler struct {
	Configuration *config.Config
	Storage       store.Storage
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(configuration *config.Config, storage store.Storage) *HealthHandler {
	return &HealthHandler{
		Configuration: configuration,
		Storage:       storage,
	}
}

// ServeHTTP handles health check requests
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	clientCount, _ := h.Storage.GetClientCount() // Ignore error for health check

	response := map[string]interface{}{
		"status":     "healthy",
		"timestamp":  time.Now().Unix(),
		"version":    Version,
		"git_commit": GitCommit,
		"build_time": BuildTime,
		"base_url":   h.Configuration.PublicBaseURL,
		"clients":    clientCount,
		"storage":    "custom", // Indicate we're using custom storage
	}

	json.NewEncoder(w).Encode(response)
}
