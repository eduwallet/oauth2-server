package storage

import (
	"database/sql"
	"fmt"

	"oauth2-server/internal/config"

	_ "github.com/lib/pq"
)

// PostgreSQLDialect implements SQLDialect for PostgreSQL
type PostgreSQLDialect struct{}

// GetCreateTableStatements returns PostgreSQL-specific CREATE TABLE statements
func (d *PostgreSQLDialect) GetCreateTableStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS auth_codes (
			code VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			response_type VARCHAR(50) NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT,
			state TEXT,
			code_challenge TEXT,
			code_challenge_method VARCHAR(10),
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS device_codes (
			device_code VARCHAR(255) PRIMARY KEY,
			user_code VARCHAR(50) UNIQUE NOT NULL,
			client_id VARCHAR(255) NOT NULL,
			scopes TEXT,
			expires_in INTEGER NOT NULL,
			interval_seconds INTEGER NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			authorized BOOLEAN DEFAULT FALSE,
			user_id VARCHAR(255),
			access_token TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS dynamic_clients (
			client_id VARCHAR(255) PRIMARY KEY,
			client_secret VARCHAR(255),
			client_name VARCHAR(255),
			description TEXT,
			redirect_uris JSONB, -- JSON array
			grant_types JSONB, -- JSON array
			response_types JSONB, -- JSON array
			scopes JSONB, -- JSON array
			token_endpoint_auth_method VARCHAR(100),
			public BOOLEAN DEFAULT FALSE,
			allowed_audiences JSONB, -- JSON array
			allow_token_exchange BOOLEAN DEFAULT FALSE,
			allowed_origins JSONB, -- JSON array
			software_id VARCHAR(255),
			software_version VARCHAR(255),
			client_id_issued_at TIMESTAMP,
			client_secret_expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS registration_tokens (
			token VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS oauth_tokens (
			token TEXT PRIMARY KEY,
			token_type VARCHAR(20) NOT NULL,
			client_id VARCHAR(255) NOT NULL,
			user_id VARCHAR(255),
			scope TEXT,
			audience JSONB,
			subject VARCHAR(255),
			issued_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			not_before TIMESTAMP,
			active BOOLEAN DEFAULT TRUE,
			extra JSONB,
			parent_access_token TEXT,
			nonce TEXT,
			auth_time TIMESTAMP,
			grant_type VARCHAR(50),
			created_at TIMESTAMP NOT NULL
		)`,
	}
}

// GetIndexStatements returns PostgreSQL-specific index creation statements
func (d *PostgreSQLDialect) GetIndexStatements() []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON auth_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_client_id ON device_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_dynamic_clients_created_at ON dynamic_clients(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_client_id ON registration_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_expires_at ON registration_tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client_id ON oauth_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires_at ON oauth_tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_tokens_token_type ON oauth_tokens(token_type)`,
	}
}

// Placeholder returns PostgreSQL parameter placeholder ($1, $2, etc.)
func (d *PostgreSQLDialect) Placeholder(n int) string {
	return fmt.Sprintf("$%d", n)
}

// GetTimestampFunction returns PostgreSQL timestamp function
func (d *PostgreSQLDialect) GetTimestampFunction() string {
	return "NOW()"
}

// GetJSONType returns PostgreSQL JSON storage type
func (d *PostgreSQLDialect) GetJSONType() string {
	return "JSONB"
}

// GetExpiredCleanupQuery returns PostgreSQL-specific cleanup query
func (d *PostgreSQLDialect) GetExpiredCleanupQuery(table, timeColumn string) string {
	return fmt.Sprintf("DELETE FROM %s WHERE %s < NOW()", table, timeColumn)
}

// PostgreSQLStorage wraps BaseSQLStorage with PostgreSQL-specific functionality
type PostgreSQLStorage struct {
	*BaseSQLStorage
}

// NewPostgreSQLStorage creates a new PostgreSQL storage instance
func NewPostgreSQLStorage(connStr string) (*PostgreSQLStorage, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL database: %w", err)
	}

	baseStorage, err := NewBaseSQLStorage(db, &PostgreSQLDialect{})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &PostgreSQLStorage{
		BaseSQLStorage: baseStorage,
	}, nil
}

// NewPostgresStorage is a convenience function that builds connection string from config
func NewPostgresStorage(cfg *config.DatabaseConfig) (*PostgreSQLStorage, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.PostgresHost,
		cfg.PostgresPort,
		cfg.PostgresUser,
		cfg.PostgresPassword,
		cfg.PostgresDB,
		cfg.PostgresSSLMode,
	)
	return NewPostgreSQLStorage(connStr)
}
