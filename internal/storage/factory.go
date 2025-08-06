package storage

import (
	"fmt"
	"log"
	"strings"

	"oauth2-server/internal/config"
)

// NewStorage creates a new storage instance based on the configuration
func NewStorage(cfg *config.DatabaseConfig) (Storage, error) {
	log.Println("Starting storage initialization...")
	log.Printf("Storage type requested: %s", cfg.Type)

	switch strings.ToLower(cfg.Type) {
	case "sqlite":
		log.Println("Initializing SQLite storage...")
		if cfg.SQLitePath == "" {
			cfg.SQLitePath = "oauth2.db"
			log.Printf("Using default SQLite path: %s", cfg.SQLitePath)
		} else {
			log.Printf("Using configured SQLite path: %s", cfg.SQLitePath)
		}
		storage, err := NewSQLiteStorage(cfg.SQLitePath)
		if err != nil {
			log.Printf("Failed to initialize SQLite storage: %v", err)
			return nil, err
		}
		log.Println("SQLite storage initialized successfully")
		return storage, nil

	case "postgres", "postgresql":
		log.Println("Initializing PostgreSQL storage...")
		storage, err := NewPostgresStorage(cfg)
		if err != nil {
			log.Printf("Failed to initialize PostgreSQL storage: %v", err)
			return nil, err
		}
		log.Println("PostgreSQL storage initialized successfully")
		return storage, nil

	case "memory", "":
		log.Println("Initializing in-memory storage...")
		storage := NewMemoryStorage()
		log.Println("In-memory storage initialized successfully")
		return storage, nil

	default:
		log.Printf("Unsupported storage type requested: %s", cfg.Type)
		err := fmt.Errorf("unsupported storage type: %s", cfg.Type)
		log.Printf("Storage initialization failed: %v", err)
		return nil, err
	}
}
