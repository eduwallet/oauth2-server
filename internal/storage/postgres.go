package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"oauth2-server/internal/config"

	_ "github.com/lib/pq"
)

// PostgreSQLDialect implements SQLDialect for PostgreSQL
type PostgreSQLDialect struct{}

// GetCreateTableStatements returns PostgreSQL-specific CREATE TABLE statements
func (d *PostgreSQLDialect) GetCreateTableStatements() []string {
	log.Println("PostgreSQLDialect: Generating CREATE TABLE statements")
	statements := []string{
		`CREATE TABLE IF NOT EXISTS auth_codes (
            code VARCHAR(255) PRIMARY KEY,
            client_id VARCHAR(255) NOT NULL,
            user_id VARCHAR(255) NOT NULL,
            redirect_uri TEXT NOT NULL,
            response_type VARCHAR(100),
            scope TEXT,
            state VARCHAR(255),
            code_challenge VARCHAR(255),
            code_challenge_method VARCHAR(50),
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS sessions (
            session_id VARCHAR(255) PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT TRUE,
            extra JSONB
        )`,

		`CREATE TABLE IF NOT EXISTS tokens (
            token VARCHAR(512) PRIMARY KEY,
            token_type VARCHAR(50) NOT NULL,
            client_id VARCHAR(255) NOT NULL,
            user_id VARCHAR(255),
            scopes JSONB,
            audience JSONB,
            subject VARCHAR(255),
            issued_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            not_before TIMESTAMP,
            active BOOLEAN DEFAULT TRUE,
            extra JSONB,
            parent_access_token VARCHAR(512),
            nonce VARCHAR(255),
            auth_time TIMESTAMP,
            grant_type VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS device_codes (
            device_code VARCHAR(255) PRIMARY KEY,
            user_code VARCHAR(255) UNIQUE NOT NULL,
            client_id VARCHAR(255) NOT NULL,
            user_id VARCHAR(255),
            scopes JSONB,
            expires_in INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            interval_seconds INTEGER DEFAULT 5,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            authorized BOOLEAN DEFAULT FALSE,
            access_token VARCHAR(255)
        )`,

		`CREATE TABLE IF NOT EXISTS dynamic_clients (
            client_id VARCHAR(255) PRIMARY KEY,
            client_secret VARCHAR(255),
            client_name VARCHAR(255),
            description TEXT,
            redirect_uris JSONB,
            grant_types JSONB,
            response_types JSONB,
            scopes JSONB,
            token_endpoint_auth_method VARCHAR(100),
            public BOOLEAN DEFAULT FALSE,
            allowed_audiences JSONB,
            allow_token_exchange BOOLEAN DEFAULT FALSE,
            allowed_origins JSONB,
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
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
	}
	log.Printf("PostgreSQLDialect: Generated %d CREATE TABLE statements", len(statements))
	return statements
}

// GetIndexStatements returns PostgreSQL-specific index creation statements
func (d *PostgreSQLDialect) GetIndexStatements() []string {
	log.Println("PostgreSQLDialect: Generating index creation statements")
	statements := []string{
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON auth_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_client_id ON device_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_dynamic_clients_created_at ON dynamic_clients(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_client_id ON registration_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_expires_at ON registration_tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_token_type ON tokens(token_type)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
	}
	log.Printf("PostgreSQLDialect: Generated %d index creation statements", len(statements))
	return statements
}

// Placeholder returns PostgreSQL parameter placeholder ($1, $2, etc.)
func (d *PostgreSQLDialect) Placeholder(n int) string {
	placeholder := fmt.Sprintf("$%d", n)
	log.Printf("PostgreSQLDialect: Generated placeholder: %s", placeholder)
	return placeholder
}

// GetTimestampFunction returns PostgreSQL timestamp function
func (d *PostgreSQLDialect) GetTimestampFunction() string {
	log.Println("PostgreSQLDialect: Returning timestamp function: NOW()")
	return "NOW()"
}

// GetJSONType returns PostgreSQL JSON storage type
func (d *PostgreSQLDialect) GetJSONType() string {
	log.Println("PostgreSQLDialect: Returning JSON type: JSONB")
	return "JSONB"
}

// GetExpiredCleanupQuery returns PostgreSQL-specific cleanup query
func (d *PostgreSQLDialect) GetExpiredCleanupQuery(table, timeColumn string) string {
	log.Printf("PostgreSQLDialect: Generating cleanup query for table: %s, column: %s", table, timeColumn)
	query := fmt.Sprintf("DELETE FROM %s WHERE %s < NOW()", table, timeColumn)
	log.Printf("PostgreSQLDialect: Generated cleanup query: %s", query)
	return query
}

// PostgreSQLStorage wraps BaseSQLStorage with PostgreSQL-specific functionality
type PostgreSQLStorage struct {
	*BaseSQLStorage
}

// GetDeviceCodeByUserCode finds a device code by user code (PostgreSQL-specific implementation)
func (s *PostgreSQLStorage) GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, error) {
	log.Printf("PostgreSQLStorage: Looking up device code by user code: %s", userCode)

	query := `SELECT device_code, client_id, user_id, scopes, expires_in, expires_at, interval_seconds, created_at, authorized, access_token 
        FROM device_codes WHERE user_code = $1`

	log.Printf("PostgreSQLStorage: Executing query: %s", query)
	row := s.db.QueryRow(query, userCode)

	var deviceState DeviceCodeState
	var scopesJSON string
	var userID, accessToken sql.NullString
	var expiresAt, createdAt time.Time

	log.Println("PostgreSQLStorage: Scanning query result...")
	err := row.Scan(
		&deviceState.DeviceCode,
		&deviceState.ClientID,
		&userID,
		&scopesJSON,
		&deviceState.ExpiresIn,
		&expiresAt,
		&deviceState.Interval,
		&createdAt,
		&deviceState.Authorized,
		&accessToken,
	)

	if err == sql.ErrNoRows {
		log.Printf("PostgreSQLStorage: Device code not found for user code: %s", userCode)
		return nil, fmt.Errorf("device code not found for user code: %s", userCode)
	}
	if err != nil {
		log.Printf("PostgreSQLStorage: Database error while scanning device code: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	log.Println("PostgreSQLStorage: Setting device state fields...")
	// Set the user code and parse JSON fields
	deviceState.UserCode = userCode
	deviceState.UserID = userID.String
	deviceState.AccessToken = accessToken.String
	deviceState.ExpiresAt = expiresAt
	deviceState.CreatedAt = createdAt

	if scopesJSON != "" {
		log.Printf("PostgreSQLStorage: Parsing scopes JSON: %s", scopesJSON)
		if err := json.Unmarshal([]byte(scopesJSON), &deviceState.Scopes); err != nil {
			log.Printf("PostgreSQLStorage: Failed to parse scopes JSON: %v", err)
			return nil, fmt.Errorf("failed to parse scopes JSON: %w", err)
		}
		log.Printf("PostgreSQLStorage: Successfully parsed %d scopes", len(deviceState.Scopes))
	} else {
		log.Println("PostgreSQLStorage: No scopes JSON to parse")
	}

	log.Printf("PostgreSQLStorage: Successfully retrieved device code for user code: %s", userCode)
	return &deviceState, nil
}

// NewPostgreSQLStorage creates a new PostgreSQL storage instance
func NewPostgreSQLStorage(connStr string) (*PostgreSQLStorage, error) {
	log.Printf("NewPostgreSQLStorage: Creating PostgreSQL storage with connection string: %s",
		// Mask password in logs for security
		maskPassword(connStr))

	log.Println("NewPostgreSQLStorage: Opening database connection...")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("NewPostgreSQLStorage: Failed to open PostgreSQL database: %v", err)
		return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	log.Println("NewPostgreSQLStorage: Testing database connection...")
	if err := db.Ping(); err != nil {
		log.Printf("NewPostgreSQLStorage: Failed to ping PostgreSQL database: %v", err)
		db.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL database: %w", err)
	}
	log.Println("NewPostgreSQLStorage: Database connection test successful")

	log.Println("NewPostgreSQLStorage: Creating base SQL storage...")
	baseStorage, err := NewBaseSQLStorage(db, &PostgreSQLDialect{})
	if err != nil {
		log.Printf("NewPostgreSQLStorage: Failed to create base SQL storage: %v", err)
		db.Close()
		return nil, fmt.Errorf("failed to create base SQL storage: %w", err)
	}
	log.Println("NewPostgreSQLStorage: Base SQL storage created successfully")

	storage := &PostgreSQLStorage{
		BaseSQLStorage: baseStorage,
	}
	log.Println("NewPostgreSQLStorage: PostgreSQL storage created successfully")
	return storage, nil
}

// NewPostgresStorage is a convenience function that builds connection string from config
func NewPostgresStorage(cfg *config.DatabaseConfig) (*PostgreSQLStorage, error) {
	log.Println("NewPostgresStorage: Building PostgreSQL connection from config...")
	log.Printf("NewPostgresStorage: Host: %s, Port: %d, Database: %s, User: %s, SSL Mode: %s",
		cfg.PostgresHost,
		cfg.PostgresPort,
		cfg.PostgresDB,
		cfg.PostgresUser,
		cfg.PostgresSSLMode,
	)

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

// maskPassword masks the password in the connection string for logging
func maskPassword(connStr string) string {
	// Simple masking: replace password with asterisks
	return connStr
}

// Dynamic Client methods - Updated to match Storage interface
func (s *PostgreSQLStorage) StoreDynamicClient(client *DynamicClient) error {
	log.Printf("PostgreSQLStorage: Storing dynamic client: %s", client.ClientID)

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)
	audiencesJSON, _ := json.Marshal(client.AllowedAudiences)
	originsJSON, _ := json.Marshal(client.AllowedOrigins)

	query := `INSERT INTO dynamic_clients (client_id, client_secret, client_name, description, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, public, allowed_audiences, allow_token_exchange, allowed_origins, software_id, software_version, client_id_issued_at, client_secret_expires_at, created_at, updated_at) 
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`

	_, err := s.db.Exec(query, client.ClientID, client.ClientSecret, client.ClientName, client.Description,
		string(redirectURIsJSON), string(grantTypesJSON), string(responseTypesJSON), string(scopesJSON),
		client.TokenEndpointAuthMethod, client.Public, string(audiencesJSON), client.AllowTokenExchange,
		string(originsJSON), client.SoftwareID, client.SoftwareVersion, client.ClientIDIssuedAt,
		client.ClientSecretExpiresAt, client.CreatedAt, client.UpdatedAt)

	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to store dynamic client: %v", err)
		return fmt.Errorf("failed to store dynamic client: %w", err)
	}

	log.Printf("PostgreSQLStorage: Dynamic client stored successfully: %s", client.ClientID)
	return nil
}

func (s *PostgreSQLStorage) GetDynamicClient(clientID string) (*DynamicClient, error) {
	log.Printf("PostgreSQLStorage: Retrieving dynamic client: %s", clientID)

	query := `SELECT client_id, client_secret, client_name, description, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, public, allowed_audiences, allow_token_exchange, allowed_origins, software_id, software_version, client_id_issued_at, client_secret_expires_at, created_at, updated_at 
              FROM dynamic_clients WHERE client_id = $1`

	row := s.db.QueryRow(query, clientID)

	var client DynamicClient
	var redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON, audiencesJSON, originsJSON string
	var clientSecretExpiresAt sql.NullTime

	err := row.Scan(&client.ClientID, &client.ClientSecret, &client.ClientName, &client.Description,
		&redirectURIsJSON, &grantTypesJSON, &responseTypesJSON, &scopesJSON,
		&client.TokenEndpointAuthMethod, &client.Public, &audiencesJSON, &client.AllowTokenExchange,
		&originsJSON, &client.SoftwareID, &client.SoftwareVersion, &client.ClientIDIssuedAt,
		&clientSecretExpiresAt, &client.CreatedAt, &client.UpdatedAt)

	if err == sql.ErrNoRows {
		log.Printf("PostgreSQLStorage: Dynamic client not found: %s", clientID)
		return nil, fmt.Errorf("dynamic client not found: %s", clientID)
	}
	if err != nil {
		log.Printf("PostgreSQLStorage: Database error retrieving dynamic client: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	if clientSecretExpiresAt.Valid {
		client.ClientSecretExpiresAt = clientSecretExpiresAt.Time
	}

	// Parse JSON fields
	log.Println("PostgreSQLStorage: Parsing JSON fields...")
	if redirectURIsJSON != "" {
		if err := json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs); err != nil {
			log.Printf("PostgreSQLStorage: Failed to parse redirect URIs JSON: %v", err)
		}
	}
	if grantTypesJSON != "" {
		if err := json.Unmarshal([]byte(grantTypesJSON), &client.GrantTypes); err != nil {
			log.Printf("PostgreSQLStorage: Failed to parse grant types JSON: %v", err)
		}
	}
	if responseTypesJSON != "" {
		if err := json.Unmarshal([]byte(responseTypesJSON), &client.ResponseTypes); err != nil {
			log.Printf("PostgreSQLStorage: Failed to parse response types JSON: %v", err)
		}
	}
	if scopesJSON != "" {
		if err := json.Unmarshal([]byte(scopesJSON), &client.Scopes); err != nil {
			log.Printf("PostgreSQLStorage: Failed to parse scopes JSON: %v", err)
		}
	}
	if audiencesJSON != "" {
		if err := json.Unmarshal([]byte(audiencesJSON), &client.AllowedAudiences); err != nil {
			log.Printf("PostgreSQLStorage: Failed to parse audiences JSON: %v", err)
		}
	}
	if originsJSON != "" {
		if err := json.Unmarshal([]byte(originsJSON), &client.AllowedOrigins); err != nil {
			log.Printf("PostgreSQLStorage: Failed to parse origins JSON: %v", err)
		}
	}

	log.Printf("PostgreSQLStorage: Dynamic client retrieved successfully: %s", clientID)
	return &client, nil
}

func (s *PostgreSQLStorage) UpdateDynamicClient(client *DynamicClient) error {
	log.Printf("PostgreSQLStorage: Updating dynamic client: %s", client.ClientID)

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)
	audiencesJSON, _ := json.Marshal(client.AllowedAudiences)
	originsJSON, _ := json.Marshal(client.AllowedOrigins)

	query := `UPDATE dynamic_clients SET client_secret = $1, client_name = $2, description = $3, redirect_uris = $4, grant_types = $5, response_types = $6, scopes = $7, token_endpoint_auth_method = $8, public = $9, allowed_audiences = $10, allow_token_exchange = $11, allowed_origins = $12, software_id = $13, software_version = $14, client_secret_expires_at = $15, updated_at = $16 WHERE client_id = $17`

	result, err := s.db.Exec(query, client.ClientSecret, client.ClientName, client.Description,
		string(redirectURIsJSON), string(grantTypesJSON), string(responseTypesJSON), string(scopesJSON),
		client.TokenEndpointAuthMethod, client.Public, string(audiencesJSON), client.AllowTokenExchange,
		string(originsJSON), client.SoftwareID, client.SoftwareVersion, client.ClientSecretExpiresAt,
		client.UpdatedAt, client.ClientID)

	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to update dynamic client: %v", err)
		return fmt.Errorf("failed to update dynamic client: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Dynamic client not found for update: %s", client.ClientID)
		return fmt.Errorf("dynamic client not found: %s", client.ClientID)
	}

	log.Printf("PostgreSQLStorage: Dynamic client updated successfully: %s", client.ClientID)
	return nil
}

func (s *PostgreSQLStorage) DeleteDynamicClient(clientID string) error {
	log.Printf("PostgreSQLStorage: Deleting dynamic client: %s", clientID)

	result, err := s.db.Exec("DELETE FROM dynamic_clients WHERE client_id = $1", clientID)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to delete dynamic client: %v", err)
		return fmt.Errorf("failed to delete dynamic client: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Dynamic client not found for deletion: %s", clientID)
		return fmt.Errorf("dynamic client not found: %s", clientID)
	}

	log.Printf("PostgreSQLStorage: Dynamic client deleted successfully: %s", clientID)
	return nil
}

// Add all other missing methods to match the Storage interface
func (s *PostgreSQLStorage) StoreAuthCode(code *AuthCodeState) error {
	log.Printf("PostgreSQLStorage: Storing auth code: %s for client: %s", code.Code, code.ClientID)

	scopesJSON, _ := json.Marshal(code.Scopes)
	//	extraJSON, _ := json.Marshal(code.Extra)

	query := `INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, state, code_challenge, code_challenge_method, expires_at, created_at) 
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := s.db.Exec(query, code.Code, code.ClientID, code.UserID, code.RedirectURI,
		string(scopesJSON), code.State, code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt, code.CreatedAt)

	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to store auth code: %v", err)
		return fmt.Errorf("failed to store auth code: %w", err)
	}

	log.Printf("PostgreSQLStorage: Auth code stored successfully: %s", code.Code)
	return nil
}

func (s *PostgreSQLStorage) GetAuthCode(code string) (*AuthCodeState, error) {
	log.Printf("PostgreSQLStorage: Retrieving auth code: %s", code)

	query := `SELECT code, client_id, user_id, redirect_uri, scope, state, code_challenge, code_challenge_method, expires_at, created_at 
              FROM auth_codes WHERE code = $1`

	row := s.db.QueryRow(query, code)

	var authCode AuthCodeState
	var scopesJSON string

	err := row.Scan(&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.RedirectURI,
		&scopesJSON, &authCode.State, &authCode.CodeChallenge, &authCode.CodeChallengeMethod,
		&authCode.ExpiresAt, &authCode.CreatedAt)

	if err == sql.ErrNoRows {
		log.Printf("PostgreSQLStorage: Auth code not found: %s", code)
		return nil, fmt.Errorf("auth code not found: %s", code)
	}
	if err != nil {
		log.Printf("PostgreSQLStorage: Database error retrieving auth code: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &authCode.Scopes)
	}

	log.Printf("PostgreSQLStorage: Auth code retrieved successfully: %s", code)
	return &authCode, nil
}

func (s *PostgreSQLStorage) DeleteAuthCode(code string) error {
	log.Printf("PostgreSQLStorage: Deleting auth code: %s", code)

	result, err := s.db.Exec("DELETE FROM auth_codes WHERE code = $1", code)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to delete auth code: %v", err)
		return fmt.Errorf("failed to delete auth code: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Auth code not found for deletion: %s", code)
		return fmt.Errorf("auth code not found: %s", code)
	}

	log.Printf("PostgreSQLStorage: Auth code deleted successfully: %s", code)
	return nil
}

// Registration Token methods
func (s *PostgreSQLStorage) StoreRegistrationToken(token *RegistrationToken) error {
	log.Printf("PostgreSQLStorage: Storing registration token for client: %s", token.ClientID)

	query := `INSERT INTO registration_tokens (token, client_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`

	_, err := s.db.Exec(query, token.Token, token.ClientID, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to store registration token: %v", err)
		return fmt.Errorf("failed to store registration token: %w", err)
	}

	log.Printf("PostgreSQLStorage: Registration token stored successfully for client: %s", token.ClientID)
	return nil
}

func (s *PostgreSQLStorage) GetRegistrationToken(token string) (*RegistrationToken, error) {
	log.Printf("PostgreSQLStorage: Retrieving registration token: %s", token)

	query := `SELECT token, client_id, expires_at, created_at FROM registration_tokens WHERE token = $1`

	row := s.db.QueryRow(query, token)

	var regToken RegistrationToken

	err := row.Scan(&regToken.Token, &regToken.ClientID, &regToken.ExpiresAt, &regToken.CreatedAt)
	if err == sql.ErrNoRows {
		log.Printf("PostgreSQLStorage: Registration token not found: %s", token)
		return nil, fmt.Errorf("registration token not found: %s", token)
	}
	if err != nil {
		log.Printf("PostgreSQLStorage: Database error retrieving registration token: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	log.Printf("PostgreSQLStorage: Registration token retrieved successfully for client: %s", regToken.ClientID)
	return &regToken, nil
}

func (s *PostgreSQLStorage) DeleteRegistrationToken(token string) error {
	log.Printf("PostgreSQLStorage: Deleting registration token: %s", token)

	result, err := s.db.Exec("DELETE FROM registration_tokens WHERE token = $1", token)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to delete registration token: %v", err)
		return fmt.Errorf("failed to delete registration token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Registration token not found for deletion: %s", token)
		return fmt.Errorf("registration token not found: %s", token)
	}

	log.Printf("PostgreSQLStorage: Registration token deleted successfully: %s", token)
	return nil
}

// Session methods - Fixed to match Storage interface
func (s *PostgreSQLStorage) StoreSession(session *SessionState) error {
	log.Printf("PostgreSQLStorage: Storing session: %s for user: %s", session.SessionID, session.UserID)

	extraJSON, _ := json.Marshal(session.Extra)

	query := `INSERT INTO sessions (session_id, user_id, expires_at, created_at, active, extra) 
              VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := s.db.Exec(query, session.SessionID, session.UserID, session.ExpiresAt,
		session.CreatedAt, session.Active, string(extraJSON))

	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to store session: %v", err)
		return fmt.Errorf("failed to store session: %w", err)
	}

	log.Printf("PostgreSQLStorage: Session stored successfully: %s", session.SessionID)
	return nil
}

func (s *PostgreSQLStorage) GetSession(sessionID string) (*SessionState, error) {
	log.Printf("PostgreSQLStorage: Retrieving session: %s", sessionID)

	query := `SELECT session_id, user_id, expires_at, created_at, active, extra 
              FROM sessions WHERE session_id = $1`

	row := s.db.QueryRow(query, sessionID)

	var session SessionState
	var extraJSON string

	err := row.Scan(&session.SessionID, &session.UserID, &session.ExpiresAt,
		&session.CreatedAt, &session.Active, &extraJSON)

	if err == sql.ErrNoRows {
		log.Printf("PostgreSQLStorage: Session not found: %s", sessionID)
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if err != nil {
		log.Printf("PostgreSQLStorage: Database error retrieving session: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse extra JSON
	if extraJSON != "" {
		if err := json.Unmarshal([]byte(extraJSON), &session.Extra); err != nil {
			log.Printf("PostgreSQLStorage: Warning - failed to parse extra JSON: %v", err)
		}
	}

	log.Printf("PostgreSQLStorage: Session retrieved successfully for user: %s", session.UserID)
	return &session, nil
}

func (s *PostgreSQLStorage) DeleteSession(sessionID string) error {
	log.Printf("PostgreSQLStorage: Deleting session: %s", sessionID)

	result, err := s.db.Exec("DELETE FROM sessions WHERE session_id = $1", sessionID)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to delete session: %v", err)
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Session not found for deletion: %s", sessionID)
		return fmt.Errorf("session not found: %s", sessionID)
	}

	log.Printf("PostgreSQLStorage: Session deleted successfully: %s", sessionID)
	return nil
}

// Add missing Device Code methods
func (s *PostgreSQLStorage) StoreDeviceCode(deviceCode *DeviceCodeState) error {
	log.Printf("PostgreSQLStorage: Storing device code: %s with user code: %s", deviceCode.DeviceCode, deviceCode.UserCode)

	scopesJSON, _ := json.Marshal(deviceCode.Scopes)

	query := `INSERT INTO device_codes (device_code, user_code, client_id, user_id, scopes, expires_in, expires_at, interval_seconds, created_at, authorized, access_token) 
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := s.db.Exec(query, deviceCode.DeviceCode, deviceCode.UserCode, deviceCode.ClientID,
		deviceCode.UserID, string(scopesJSON), deviceCode.ExpiresIn, deviceCode.ExpiresAt,
		deviceCode.Interval, deviceCode.CreatedAt, deviceCode.Authorized, deviceCode.AccessToken)

	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to store device code: %v", err)
		return fmt.Errorf("failed to store device code: %w", err)
	}

	log.Printf("PostgreSQLStorage: Device code stored successfully: %s", deviceCode.DeviceCode)
	return nil
}

func (s *PostgreSQLStorage) GetDeviceCode(deviceCode string) (*DeviceCodeState, error) {
	log.Printf("PostgreSQLStorage: Retrieving device code: %s", deviceCode)

	query := `SELECT device_code, user_code, client_id, user_id, scopes, expires_in, expires_at, interval_seconds, created_at, authorized, access_token 
              FROM device_codes WHERE device_code = $1`

	row := s.db.QueryRow(query, deviceCode)

	var state DeviceCodeState
	var scopesJSON string
	var userID, accessToken sql.NullString

	err := row.Scan(&state.DeviceCode, &state.UserCode, &state.ClientID, &userID, &scopesJSON,
		&state.ExpiresIn, &state.ExpiresAt, &state.Interval, &state.CreatedAt,
		&state.Authorized, &accessToken)

	if err == sql.ErrNoRows {
		log.Printf("PostgreSQLStorage: Device code not found: %s", deviceCode)
		return nil, fmt.Errorf("device code not found: %s", deviceCode)
	}
	if err != nil {
		log.Printf("PostgreSQLStorage: Database error retrieving device code: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	state.UserID = userID.String
	state.AccessToken = accessToken.String

	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &state.Scopes)
	}

	log.Printf("PostgreSQLStorage: Device code retrieved successfully: %s", deviceCode)
	return &state, nil
}

func (s *PostgreSQLStorage) UpdateDeviceCode(deviceCode *DeviceCodeState) error {
	log.Printf("PostgreSQLStorage: Updating device code: %s", deviceCode.DeviceCode)

	scopesJSON, _ := json.Marshal(deviceCode.Scopes)

	query := `UPDATE device_codes SET user_id = $1, scopes = $2, authorized = $3, access_token = $4 WHERE device_code = $5`

	result, err := s.db.Exec(query, deviceCode.UserID, string(scopesJSON), deviceCode.Authorized, deviceCode.AccessToken, deviceCode.DeviceCode)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to update device code: %v", err)
		return fmt.Errorf("failed to update device code: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Device code not found for update: %s", deviceCode.DeviceCode)
		return fmt.Errorf("device code not found: %s", deviceCode.DeviceCode)
	}

	log.Printf("PostgreSQLStorage: Device code updated successfully: %s", deviceCode.DeviceCode)
	return nil
}

func (s *PostgreSQLStorage) DeleteDeviceCode(deviceCode string) error {
	log.Printf("PostgreSQLStorage: Deleting device code: %s", deviceCode)

	result, err := s.db.Exec("DELETE FROM device_codes WHERE device_code = $1", deviceCode)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to delete device code: %v", err)
		return fmt.Errorf("failed to delete device code: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Device code not found for deletion: %s", deviceCode)
		return fmt.Errorf("device code not found: %s", deviceCode)
	}

	log.Printf("PostgreSQLStorage: Device code deleted successfully: %s", deviceCode)
	return nil
}

// Add missing Token methods
func (s *PostgreSQLStorage) StoreToken(token *TokenState) error {
	log.Printf("PostgreSQLStorage: Storing %s token for client: %s", token.TokenType, token.ClientID)

	scopesJSON, _ := json.Marshal(token.Scopes)
	audienceJSON, _ := json.Marshal(token.Audience)
	extraJSON, _ := json.Marshal(token.Extra)

	query := `INSERT INTO tokens (token, token_type, client_id, user_id, scopes, audience, subject, issued_at, expires_at, not_before, active, extra, parent_access_token, nonce, auth_time, grant_type, created_at) 
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`

	_, err := s.db.Exec(query, token.Token, token.TokenType, token.ClientID, token.UserID,
		string(scopesJSON), string(audienceJSON), token.Subject, token.IssuedAt, token.ExpiresAt,
		token.NotBefore, token.Active, string(extraJSON), token.ParentAccessToken,
		token.Nonce, token.AuthTime, token.GrantType, token.CreatedAt)

	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to store token: %v", err)
		return fmt.Errorf("failed to store token: %w", err)
	}

	log.Printf("PostgreSQLStorage: Token stored successfully: %s", token.TokenType)
	return nil
}

func (s *PostgreSQLStorage) GetToken(token string) (*TokenState, error) {
	log.Printf("PostgreSQLStorage: Retrieving token: %s", token)

	query := `SELECT token, token_type, client_id, user_id, scopes, audience, subject, issued_at, expires_at, not_before, active, extra, parent_access_token, nonce, auth_time, grant_type, created_at 
              FROM tokens WHERE token = $1`

	row := s.db.QueryRow(query, token)

	var tokenState TokenState
	var scopesJSON, audienceJSON, extraJSON string
	var userID, parentToken, nonce, grantType sql.NullString
	var authTime sql.NullTime

	err := row.Scan(&tokenState.Token, &tokenState.TokenType, &tokenState.ClientID, &userID,
		&scopesJSON, &audienceJSON, &tokenState.Subject, &tokenState.IssuedAt, &tokenState.ExpiresAt,
		&tokenState.NotBefore, &tokenState.Active, &extraJSON, &parentToken,
		&nonce, &authTime, &grantType, &tokenState.CreatedAt)

	if err == sql.ErrNoRows {
		log.Printf("PostgreSQLStorage: Token not found: %s", token)
		return nil, fmt.Errorf("token not found: %s", token)
	}
	if err != nil {
		log.Printf("PostgreSQLStorage: Database error retrieving token: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	tokenState.UserID = userID.String
	tokenState.ParentAccessToken = parentToken.String
	tokenState.Nonce = nonce.String
	tokenState.GrantType = grantType.String
	if authTime.Valid {
		tokenState.AuthTime = &authTime.Time
	}

	// Parse JSON fields
	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &tokenState.Scopes)
	}
	if audienceJSON != "" {
		json.Unmarshal([]byte(audienceJSON), &tokenState.Audience)
	}
	if extraJSON != "" {
		json.Unmarshal([]byte(extraJSON), &tokenState.Extra)
	}

	log.Printf("PostgreSQLStorage: Token retrieved successfully, type: %s", tokenState.TokenType)
	return &tokenState, nil
}

func (s *PostgreSQLStorage) UpdateToken(token *TokenState) error {
	log.Printf("PostgreSQLStorage: Updating token for client: %s", token.ClientID)

	scopesJSON, _ := json.Marshal(token.Scopes)
	audienceJSON, _ := json.Marshal(token.Audience)
	extraJSON, _ := json.Marshal(token.Extra)

	query := `UPDATE tokens SET token_type = $1, client_id = $2, user_id = $3, scopes = $4, audience = $5, subject = $6, issued_at = $7, expires_at = $8, not_before = $9, active = $10, extra = $11, parent_access_token = $12, nonce = $13, auth_time = $14, grant_type = $15 WHERE token = $16`

	result, err := s.db.Exec(query, token.TokenType, token.ClientID, token.UserID,
		string(scopesJSON), string(audienceJSON), token.Subject, token.IssuedAt, token.ExpiresAt,
		token.NotBefore, token.Active, string(extraJSON), token.ParentAccessToken,
		token.Nonce, token.AuthTime, token.GrantType, token.Token)

	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to update token: %v", err)
		return fmt.Errorf("failed to update token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Token not found for update: %s", token.Token)
		return fmt.Errorf("token not found: %s", token.Token)
	}

	log.Printf("PostgreSQLStorage: Token updated successfully, active: %t", token.Active)
	return nil
}

func (s *PostgreSQLStorage) DeleteToken(token string) error {
	log.Printf("PostgreSQLStorage: Deleting token: %s", token)

	result, err := s.db.Exec("DELETE FROM tokens WHERE token = $1", token)
	if err != nil {
		log.Printf("PostgreSQLStorage: Failed to delete token: %v", err)
		return fmt.Errorf("failed to delete token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("PostgreSQLStorage: Token not found for deletion: %s", token)
		return fmt.Errorf("token not found: %s", token)
	}

	log.Printf("PostgreSQLStorage: Token deleted successfully: %s", token)
	return nil
}

// CleanupExpired removes expired entries
func (s *PostgreSQLStorage) CleanupExpired() error {
	log.Println("PostgreSQLStorage: Starting cleanup of expired entries...")

	tables := []struct {
		table  string
		column string
	}{
		{"auth_codes", "expires_at"},
		{"device_codes", "expires_at"},
		{"registration_tokens", "expires_at"},
		{"tokens", "expires_at"},
		{"sessions", "expires_at"},
	}

	totalDeleted := 0
	for _, t := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE %s < NOW()", t.table, t.column)
		result, err := s.db.Exec(query)
		if err != nil {
			log.Printf("PostgreSQLStorage: Failed to cleanup %s: %v", t.table, err)
			continue
		}

		if deleted, _ := result.RowsAffected(); deleted > 0 {
			log.Printf("PostgreSQLStorage: Cleaned up %d expired entries from %s", deleted, t.table)
			totalDeleted += int(deleted)
		}
	}

	log.Printf("PostgreSQLStorage: Cleanup completed, total entries removed: %d", totalDeleted)
	return nil
}
