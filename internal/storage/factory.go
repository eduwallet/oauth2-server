package storage

import (
	"fmt"
	"strings"

	"oauth2-demo/internal/config"
)

// NewStorage creates a new storage instance based on the configuration
func NewStorage(cfg *config.DatabaseConfig) (Storage, error) {
	switch strings.ToLower(cfg.Type) {
	case "sqlite":
		if cfg.SQLitePath == "" {
			cfg.SQLitePath = "oauth2.db"
		}
		return NewSQLiteStorage(cfg.SQLitePath)
	case "postgres", "postgresql":
		return NewPostgresStorage(cfg)
	case "memory", "":
		return NewMemoryStorage(), nil
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", cfg.Type)
	}
}
