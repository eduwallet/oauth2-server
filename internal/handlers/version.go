package handlers

import (
	"encoding/json"
	"net/http"
)

// Version information - these will be set at build time
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// VersionInfo holds the version information
type VersionInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	Server    string `json:"server"`
}

// VersionHandler provides version information
type VersionHandler struct{}

// NewVersionHandler creates a new version handler
func NewVersionHandler() *VersionHandler {
	return &VersionHandler{}
}

// ServeHTTP handles version information requests
func (h *VersionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	version := VersionInfo{
		Version:   Version,
		GitCommit: GitCommit,
		BuildTime: BuildTime,
		Server:    "OAuth2 Authorization Server",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(version)
}

// SetVersionInfo sets the version information (called from main)
func SetVersionInfo(version, gitCommit, buildTime string) {
	Version = version
	GitCommit = gitCommit
	BuildTime = buildTime
}
