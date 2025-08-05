package storage

import (
	"database/sql"
	"fmt"

	_ "github.com/glebarez/go-sqlite"
)

// SQLiteDialect implements SQLDialect for SQLite
type SQLiteDialect struct{}

// GetCreateTableStatements returns SQLite-specific CREATE TABLE statements
func (d *SQLiteDialect) GetCreateTableStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS auth_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			response_type TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT,
			state TEXT,
			code_challenge TEXT,
			code_challenge_method TEXT,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS device_codes (
			device_code TEXT PRIMARY KEY,
			user_code TEXT UNIQUE NOT NULL,
			verification_uri TEXT NOT NULL,
			verification_uri_complete TEXT,
			expires_in INTEGER NOT NULL,
			interval INTEGER NOT NULL,
			client_id TEXT NOT NULL,
			scope TEXT,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			authorized BOOLEAN DEFAULT FALSE,
			user_id TEXT,
			access_token TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS dynamic_clients (
			client_id TEXT PRIMARY KEY,
			client_secret TEXT,
			client_name TEXT,
			description TEXT,
			redirect_uris TEXT,
			grant_types TEXT,
			response_types TEXT,
			scope TEXT,
			audience TEXT,
			token_endpoint_auth_method TEXT,
			public BOOLEAN DEFAULT FALSE,
			enabled_flows TEXT,
			software_id TEXT,
			software_version TEXT,
			client_id_issued_at DATETIME NOT NULL,
			client_secret_expires_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS registration_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS oauth_tokens (
			token TEXT PRIMARY KEY,
			token_type TEXT NOT NULL,
			client_id TEXT NOT NULL,
			user_id TEXT,
			scope TEXT,
			audience TEXT,
			subject TEXT,
			issued_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			not_before DATETIME,
			active BOOLEAN DEFAULT TRUE,
			extra TEXT,
			parent_access_token TEXT,
			nonce TEXT,
			auth_time DATETIME,
			grant_type TEXT,
			created_at DATETIME NOT NULL
		)`,
	}
}

// GetIndexStatements returns SQLite-specific index creation statements
func (d *SQLiteDialect) GetIndexStatements() []string {
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

// Placeholder returns SQLite parameter placeholder (always ?)
func (d *SQLiteDialect) Placeholder(n int) string {
	return "?"
}

// GetTimestampFunction returns SQLite timestamp function
func (d *SQLiteDialect) GetTimestampFunction() string {
	return "CURRENT_TIMESTAMP"
}

// GetJSONType returns SQLite JSON storage type
func (d *SQLiteDialect) GetJSONType() string {
	return "TEXT"
}

// GetExpiredCleanupQuery returns SQLite-specific cleanup query
func (d *SQLiteDialect) GetExpiredCleanupQuery(table, timeColumn string) string {
	return fmt.Sprintf("DELETE FROM %s WHERE %s < CURRENT_TIMESTAMP", table, timeColumn)
}

// SQLiteStorage wraps BaseSQLStorage with SQLite-specific functionality
type SQLiteStorage struct {
	*BaseSQLStorage
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite", dbPath+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	baseStorage, err := NewBaseSQLStorage(db, &SQLiteDialect{})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &SQLiteStorage{
		BaseSQLStorage: baseStorage,
	}, nil
}
