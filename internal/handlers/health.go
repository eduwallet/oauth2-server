package handlers

import (
	"encoding/json"
	"net/http"
	"oauth2-server/pkg/config"
	"time"

	"github.com/ory/fosite/storage"
)

// HealthHandler manages health check requests
type HealthHandler struct {
	Configuration *config.Config
	MemoryStore   *storage.MemoryStore
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(configuration *config.Config, memoryStore *storage.MemoryStore) *HealthHandler {
	return &HealthHandler{
		Configuration: configuration,
		MemoryStore:   memoryStore,
	}
}

// ServeHTTP handles health check requests
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   Version,
		"git_commit": GitCommit,
		"build_time": BuildTime,
		"base_url":  h.Configuration.Server.BaseURL,
		"clients":   len(h.MemoryStore.Clients),
		"storage":   "fosite-memory", // Indicate we're using fosite's storage
	}

	json.NewEncoder(w).Encode(response)
}
