package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

// SQLiteDialect implements SQLDialect for SQLite
type SQLiteDialect struct{}

// GetCreateTableStatements returns SQLite-specific CREATE TABLE statements
func (d *SQLiteDialect) GetCreateTableStatements() []string {
	log.Println("SQLiteDialect: Generating CREATE TABLE statements")
	statements := []string{
		`CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            state TEXT,
            code_challenge TEXT,
            code_challenge_method TEXT,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS device_codes (
            device_code TEXT PRIMARY KEY,
            user_code TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            user_id TEXT,
            scopes TEXT,
            expires_in INTEGER NOT NULL,
            expires_at DATETIME NOT NULL,
            interval_seconds INTEGER DEFAULT 5,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            authorized BOOLEAN DEFAULT FALSE,
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
            scopes TEXT,
            token_endpoint_auth_method TEXT,
            public BOOLEAN DEFAULT FALSE,
            allowed_audiences TEXT,
            allow_token_exchange BOOLEAN DEFAULT FALSE,
            allowed_origins TEXT,
            software_id TEXT,
            software_version TEXT,
            client_id_issued_at DATETIME,
            client_secret_expires_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS registration_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            token_type TEXT NOT NULL,
            client_id TEXT NOT NULL,
            user_id TEXT,
            scopes TEXT,
            audience TEXT,
            issued_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            extra TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,
	}
	log.Printf("SQLiteDialect: Generated %d CREATE TABLE statements", len(statements))
	return statements
}

// GetIndexStatements returns SQLite-specific index creation statements
func (d *SQLiteDialect) GetIndexStatements() []string {
	log.Println("SQLiteDialect: Generating index creation statements")
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
	log.Printf("SQLiteDialect: Generated %d index creation statements", len(statements))
	return statements
}

// Placeholder returns SQLite parameter placeholder (?, ?, etc.)
func (d *SQLiteDialect) Placeholder(n int) string {
	log.Printf("SQLiteDialect: Generated placeholder: ?")
	return "?"
}

// GetTimestampFunction returns SQLite timestamp function
func (d *SQLiteDialect) GetTimestampFunction() string {
	log.Println("SQLiteDialect: Returning timestamp function: datetime('now')")
	return "datetime('now')"
}

// GetJSONType returns SQLite JSON storage type
func (d *SQLiteDialect) GetJSONType() string {
	log.Println("SQLiteDialect: Returning JSON type: TEXT")
	return "TEXT"
}

// GetExpiredCleanupQuery returns SQLite-specific cleanup query
func (d *SQLiteDialect) GetExpiredCleanupQuery(table, timeColumn string) string {
	log.Printf("SQLiteDialect: Generating cleanup query for table: %s, column: %s", table, timeColumn)
	query := fmt.Sprintf("DELETE FROM %s WHERE %s < datetime('now')", table, timeColumn)
	log.Printf("SQLiteDialect: Generated cleanup query: %s", query)
	return query
}

// SQLiteStorage wraps BaseSQLStorage with SQLite-specific functionality
type SQLiteStorage struct {
	*BaseSQLStorage
	dbPath string
}

// Authorization Code methods
func (s *SQLiteStorage) StoreAuthCode(code *AuthCodeState) error {
	log.Printf("SQLiteStorage: Storing auth code: %s for client: %s", code.Code, code.ClientID)

	scopesJSON, _ := json.Marshal(code.Scopes)
	//  extraJSON, _ := json.Marshal(code.Extra)

	query := `INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, state, code_challenge, code_challenge_method, expires_at, created_at) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query, code.Code, code.ClientID, code.UserID, code.RedirectURI,
		string(scopesJSON), code.State, code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt, code.CreatedAt)

	if err != nil {
		log.Printf("SQLiteStorage: Failed to store auth code: %v", err)
		return fmt.Errorf("failed to store auth code: %w", err)
	}

	log.Printf("SQLiteStorage: Auth code stored successfully: %s", code.Code)
	return nil
}

func (s *SQLiteStorage) GetAuthCode(code string) (*AuthCodeState, error) {
	log.Printf("SQLiteStorage: Retrieving auth code: %s", code)

	query := `SELECT code, client_id, user_id, redirect_uri, scope, state, code_challenge, code_challenge_method, expires_at, created_at 
              FROM auth_codes WHERE code = ?`

	row := s.db.QueryRow(query, code)

	var authCode AuthCodeState
	var scopesJSON string

	err := row.Scan(&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.RedirectURI,
		&scopesJSON, &authCode.State, &authCode.CodeChallenge, &authCode.CodeChallengeMethod,
		&authCode.ExpiresAt, &authCode.CreatedAt)

	if err == sql.ErrNoRows {
		log.Printf("SQLiteStorage: Auth code not found: %s", code)
		return nil, fmt.Errorf("auth code not found: %s", code)
	}
	if err != nil {
		log.Printf("SQLiteStorage: Database error retrieving auth code: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &authCode.Scopes)
	}

	log.Printf("SQLiteStorage: Auth code retrieved successfully: %s", code)
	return &authCode, nil
}

func (s *SQLiteStorage) DeleteAuthCode(code string) error {
	log.Printf("SQLiteStorage: Deleting auth code: %s", code)

	result, err := s.db.Exec("DELETE FROM auth_codes WHERE code = ?", code)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to delete auth code: %v", err)
		return fmt.Errorf("failed to delete auth code: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Auth code not found for deletion: %s", code)
		return fmt.Errorf("auth code not found: %s", code)
	}

	log.Printf("SQLiteStorage: Auth code deleted successfully: %s", code)
	return nil
}

// Device Code methods
func (s *SQLiteStorage) StoreDeviceCode(deviceCode *DeviceCodeState) error {
	log.Printf("SQLiteStorage: Storing device code: %s with user code: %s", deviceCode.DeviceCode, deviceCode.UserCode)

	scopesJSON, _ := json.Marshal(deviceCode.Scopes)

	query := `INSERT INTO device_codes (device_code, user_code, client_id, user_id, scopes, expires_in, expires_at, interval_seconds, created_at, authorized, access_token) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query, deviceCode.DeviceCode, deviceCode.UserCode, deviceCode.ClientID,
		deviceCode.UserID, string(scopesJSON), deviceCode.ExpiresIn, deviceCode.ExpiresAt,
		deviceCode.Interval, deviceCode.CreatedAt, deviceCode.Authorized, deviceCode.AccessToken)

	if err != nil {
		log.Printf("SQLiteStorage: Failed to store device code: %v", err)
		return fmt.Errorf("failed to store device code: %w", err)
	}

	log.Printf("SQLiteStorage: Device code stored successfully: %s", deviceCode.DeviceCode)
	return nil
}

func (s *SQLiteStorage) GetDeviceCode(deviceCode string) (*DeviceCodeState, error) {
	log.Printf("SQLiteStorage: Retrieving device code: %s", deviceCode)

	query := `SELECT device_code, user_code, client_id, user_id, scopes, expires_in, expires_at, interval_seconds, created_at, authorized, access_token 
              FROM device_codes WHERE device_code = ?`

	row := s.db.QueryRow(query, deviceCode)

	var state DeviceCodeState
	var scopesJSON string
	var userID, accessToken sql.NullString

	err := row.Scan(&state.DeviceCode, &state.UserCode, &state.ClientID, &userID, &scopesJSON,
		&state.ExpiresIn, &state.ExpiresAt, &state.Interval, &state.CreatedAt,
		&state.Authorized, &accessToken)

	if err == sql.ErrNoRows {
		log.Printf("SQLiteStorage: Device code not found: %s", deviceCode)
		return nil, fmt.Errorf("device code not found: %s", deviceCode)
	}
	if err != nil {
		log.Printf("SQLiteStorage: Database error retrieving device code: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	state.UserID = userID.String
	state.AccessToken = accessToken.String

	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &state.Scopes)
	}

	log.Printf("SQLiteStorage: Device code retrieved successfully: %s", deviceCode)
	return &state, nil
}

// GetDeviceCodeByUserCode finds a device code by user code (SQLite-specific implementation)
func (s *SQLiteStorage) GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, error) {
	log.Printf("SQLiteStorage: Looking up device code by user code: %s", userCode)

	query := `SELECT device_code, client_id, user_id, scopes, expires_in, expires_at, interval_seconds, created_at, authorized, access_token 
        FROM device_codes WHERE user_code = ?`

	log.Printf("SQLiteStorage: Executing query: %s", query)
	row := s.db.QueryRow(query, userCode)

	var deviceState DeviceCodeState
	var scopesJSON string
	var userID, accessToken sql.NullString
	var expiresAt, createdAt time.Time

	log.Println("SQLiteStorage: Scanning query result...")
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
		log.Printf("SQLiteStorage: Device code not found for user code: %s", userCode)
		return nil, fmt.Errorf("device code not found for user code: %s", userCode)
	}
	if err != nil {
		log.Printf("SQLiteStorage: Database error while scanning device code: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	log.Println("SQLiteStorage: Setting device state fields...")
	// Set the user code and parse JSON fields
	deviceState.UserCode = userCode
	deviceState.UserID = userID.String
	deviceState.AccessToken = accessToken.String
	deviceState.ExpiresAt = expiresAt
	deviceState.CreatedAt = createdAt

	if scopesJSON != "" {
		log.Printf("SQLiteStorage: Parsing scopes JSON: %s", scopesJSON)
		if err := json.Unmarshal([]byte(scopesJSON), &deviceState.Scopes); err != nil {
			log.Printf("SQLiteStorage: Failed to parse scopes JSON: %v", err)
			return nil, fmt.Errorf("failed to parse scopes JSON: %w", err)
		}
		log.Printf("SQLiteStorage: Successfully parsed %d scopes", len(deviceState.Scopes))
	} else {
		log.Println("SQLiteStorage: No scopes JSON to parse")
	}

	log.Printf("SQLiteStorage: Successfully retrieved device code for user code: %s", userCode)
	return &deviceState, nil
}

func (s *SQLiteStorage) UpdateDeviceCode(deviceCode *DeviceCodeState) error {
	log.Printf("SQLiteStorage: Updating device code: %s", deviceCode.DeviceCode)

	scopesJSON, _ := json.Marshal(deviceCode.Scopes)

	query := `UPDATE device_codes SET user_id = ?, scopes = ?, authorized = ?, access_token = ? WHERE device_code = ?`

	result, err := s.db.Exec(query, deviceCode.UserID, string(scopesJSON), deviceCode.Authorized, deviceCode.AccessToken, deviceCode.DeviceCode)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to update device code: %v", err)
		return fmt.Errorf("failed to update device code: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Device code not found for update: %s", deviceCode.DeviceCode)
		return fmt.Errorf("device code not found: %s", deviceCode.DeviceCode)
	}

	log.Printf("SQLiteStorage: Device code updated successfully: %s", deviceCode.DeviceCode)
	return nil
}

func (s *SQLiteStorage) DeleteDeviceCode(deviceCode string) error {
	log.Printf("SQLiteStorage: Deleting device code: %s", deviceCode)

	result, err := s.db.Exec("DELETE FROM device_codes WHERE device_code = ?", deviceCode)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to delete device code: %v", err)
		return fmt.Errorf("failed to delete device code: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Device code not found for deletion: %s", deviceCode)
		return fmt.Errorf("device code not found: %s", deviceCode)
	}

	log.Printf("SQLiteStorage: Device code deleted successfully: %s", deviceCode)
	return nil
}

// Dynamic Client methods
func (s *SQLiteStorage) StoreDynamicClient(client *DynamicClient) error {
	log.Printf("SQLiteStorage: Storing dynamic client: %s", client.ClientID)

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)
	audiencesJSON, _ := json.Marshal(client.AllowedAudiences)
	originsJSON, _ := json.Marshal(client.AllowedOrigins)

	query := `INSERT INTO dynamic_clients (client_id, client_secret, client_name, description, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, public, allowed_audiences, allow_token_exchange, allowed_origins, software_id, software_version, client_id_issued_at, client_secret_expires_at, created_at, updated_at) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query, client.ClientID, client.ClientSecret, client.ClientName, client.Description,
		string(redirectURIsJSON), string(grantTypesJSON), string(responseTypesJSON), string(scopesJSON),
		client.TokenEndpointAuthMethod, client.Public, string(audiencesJSON), client.AllowTokenExchange,
		string(originsJSON), client.SoftwareID, client.SoftwareVersion, client.ClientIDIssuedAt,
		client.ClientSecretExpiresAt, client.CreatedAt, client.UpdatedAt)

	if err != nil {
		log.Printf("SQLiteStorage: Failed to store dynamic client: %v", err)
		return fmt.Errorf("failed to store dynamic client: %w", err)
	}

	log.Printf("SQLiteStorage: Dynamic client stored successfully: %s", client.ClientID)
	return nil
}

func (s *SQLiteStorage) GetDynamicClient(clientID string) (*DynamicClient, error) {
	log.Printf("SQLiteStorage: Retrieving dynamic client: %s", clientID)

	query := `SELECT client_id, client_secret, client_name, description, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, public, allowed_audiences, allow_token_exchange, allowed_origins, software_id, software_version, client_id_issued_at, client_secret_expires_at, created_at, updated_at 
              FROM dynamic_clients WHERE client_id = ?`

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
		log.Printf("SQLiteStorage: Dynamic client not found: %s", clientID)
		return nil, fmt.Errorf("dynamic client not found: %s", clientID)
	}
	if err != nil {
		log.Printf("SQLiteStorage: Database error retrieving dynamic client: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	if clientSecretExpiresAt.Valid {
		client.ClientSecretExpiresAt = clientSecretExpiresAt.Time
	}

	// Parse JSON fields
	if redirectURIsJSON != "" {
		json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs)
	}
	if grantTypesJSON != "" {
		json.Unmarshal([]byte(grantTypesJSON), &client.GrantTypes)
	}
	if responseTypesJSON != "" {
		json.Unmarshal([]byte(responseTypesJSON), &client.ResponseTypes)
	}
	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &client.Scopes)
	}
	if audiencesJSON != "" {
		json.Unmarshal([]byte(audiencesJSON), &client.AllowedAudiences)
	}
	if originsJSON != "" {
		json.Unmarshal([]byte(originsJSON), &client.AllowedOrigins)
	}

	log.Printf("SQLiteStorage: Dynamic client retrieved successfully: %s", clientID)
	return &client, nil
}

func (s *SQLiteStorage) UpdateDynamicClient(client *DynamicClient) error {
	log.Printf("SQLiteStorage: Updating dynamic client: %s", client.ClientID)

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	scopesJSON, _ := json.Marshal(client.Scopes)
	audiencesJSON, _ := json.Marshal(client.AllowedAudiences)
	originsJSON, _ := json.Marshal(client.AllowedOrigins)

	query := `UPDATE dynamic_clients SET client_secret = ?, client_name = ?, description = ?, redirect_uris = ?, grant_types = ?, response_types = ?, scopes = ?, token_endpoint_auth_method = ?, public = ?, allowed_audiences = ?, allow_token_exchange = ?, allowed_origins = ?, software_id = ?, software_version = ?, client_secret_expires_at = ?, updated_at = ? WHERE client_id = ?`

	result, err := s.db.Exec(query, client.ClientSecret, client.ClientName, client.Description,
		string(redirectURIsJSON), string(grantTypesJSON), string(responseTypesJSON), string(scopesJSON),
		client.TokenEndpointAuthMethod, client.Public, string(audiencesJSON), client.AllowTokenExchange,
		string(originsJSON), client.SoftwareID, client.SoftwareVersion, client.ClientSecretExpiresAt,
		client.UpdatedAt, client.ClientID)

	if err != nil {
		log.Printf("SQLiteStorage: Failed to update dynamic client: %v", err)
		return fmt.Errorf("failed to update dynamic client: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Dynamic client not found for update: %s", client.ClientID)
		return fmt.Errorf("dynamic client not found: %s", client.ClientID)
	}

	log.Printf("SQLiteStorage: Dynamic client updated successfully: %s", client.ClientID)
	return nil
}

func (s *SQLiteStorage) DeleteDynamicClient(clientID string) error {
	log.Printf("SQLiteStorage: Deleting dynamic client: %s", clientID)

	result, err := s.db.Exec("DELETE FROM dynamic_clients WHERE client_id = ?", clientID)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to delete dynamic client: %v", err)
		return fmt.Errorf("failed to delete dynamic client: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Dynamic client not found for deletion: %s", clientID)
		return fmt.Errorf("dynamic client not found: %s", clientID)
	}

	log.Printf("SQLiteStorage: Dynamic client deleted successfully: %s", clientID)
	return nil
}

// Registration Token methods
func (s *SQLiteStorage) StoreRegistrationToken(token *RegistrationToken) error {
	log.Printf("SQLiteStorage: Storing registration token for client: %s", token.ClientID)

	query := `INSERT INTO registration_tokens (token, client_id, expires_at, created_at) VALUES (?, ?, ?, ?)`

	_, err := s.db.Exec(query, token.Token, token.ClientID, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to store registration token: %v", err)
		return fmt.Errorf("failed to store registration token: %w", err)
	}

	log.Printf("SQLiteStorage: Registration token stored successfully for client: %s", token.ClientID)
	return nil
}

func (s *SQLiteStorage) GetRegistrationToken(token string) (*RegistrationToken, error) {
	log.Printf("SQLiteStorage: Retrieving registration token: %s", token)

	query := `SELECT token, client_id, expires_at, created_at FROM registration_tokens WHERE token = ?`

	row := s.db.QueryRow(query, token)

	var regToken RegistrationToken

	err := row.Scan(&regToken.Token, &regToken.ClientID, &regToken.ExpiresAt, &regToken.CreatedAt)
	if err == sql.ErrNoRows {
		log.Printf("SQLiteStorage: Registration token not found: %s", token)
		return nil, fmt.Errorf("registration token not found: %s", token)
	}
	if err != nil {
		log.Printf("SQLiteStorage: Database error retrieving registration token: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	log.Printf("SQLiteStorage: Registration token retrieved successfully for client: %s", regToken.ClientID)
	return &regToken, nil
}

func (s *SQLiteStorage) DeleteRegistrationToken(token string) error {
	log.Printf("SQLiteStorage: Deleting registration token: %s", token)

	result, err := s.db.Exec("DELETE FROM registration_tokens WHERE token = ?", token)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to delete registration token: %v", err)
		return fmt.Errorf("failed to delete registration token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Registration token not found for deletion: %s", token)
		return fmt.Errorf("registration token not found: %s", token)
	}

	log.Printf("SQLiteStorage: Registration token deleted successfully: %s", token)
	return nil
}

// Token methods
func (s *SQLiteStorage) StoreToken(token *TokenState) error {
	log.Printf("SQLiteStorage: Storing %s token for client: %s", token.TokenType, token.ClientID)

	scopesJSON, _ := json.Marshal(token.Scopes)
	audienceJSON, _ := json.Marshal(token.Audience)
	extraJSON, _ := json.Marshal(token.Extra)

	query := `INSERT INTO tokens (token, token_type, client_id, user_id, scopes, audience, issued_at, expires_at, active, extra, created_at) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query, token.Token, token.TokenType, token.ClientID, token.UserID,
		string(scopesJSON), string(audienceJSON), token.IssuedAt, token.ExpiresAt,
		token.Active, string(extraJSON), token.CreatedAt)

	if err != nil {
		log.Printf("SQLiteStorage: Failed to store token: %v", err)
		return fmt.Errorf("failed to store token: %w", err)
	}

	log.Printf("SQLiteStorage: Token stored successfully: %s", token.TokenType)
	return nil
}

func (s *SQLiteStorage) GetToken(token string) (*TokenState, error) {
	log.Printf("SQLiteStorage: Retrieving token: %s", token)

	query := `SELECT token, token_type, client_id, user_id, scopes, audience, issued_at, expires_at, active, extra, created_at 
              FROM tokens WHERE token = ?`

	row := s.db.QueryRow(query, token)

	var tokenState TokenState
	var scopesJSON, audienceJSON, extraJSON string
	var userID sql.NullString

	err := row.Scan(&tokenState.Token, &tokenState.TokenType, &tokenState.ClientID, &userID,
		&scopesJSON, &audienceJSON, &tokenState.IssuedAt, &tokenState.ExpiresAt,
		&tokenState.Active, &extraJSON, &tokenState.CreatedAt)

	if err == sql.ErrNoRows {
		log.Printf("SQLiteStorage: Token not found: %s", token)
		return nil, fmt.Errorf("token not found: %s", token)
	}
	if err != nil {
		log.Printf("SQLiteStorage: Database error retrieving token: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	tokenState.UserID = userID.String

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

	log.Printf("SQLiteStorage: Token retrieved successfully, type: %s", tokenState.TokenType)
	return &tokenState, nil
}

func (s *SQLiteStorage) UpdateToken(token *TokenState) error {
	log.Printf("SQLiteStorage: Updating token for client: %s", token.ClientID)

	scopesJSON, _ := json.Marshal(token.Scopes)
	audienceJSON, _ := json.Marshal(token.Audience)
	extraJSON, _ := json.Marshal(token.Extra)

	query := `UPDATE tokens SET token_type = ?, client_id = ?, user_id = ?, scopes = ?, audience = ?, issued_at = ?, expires_at = ?, active = ?, extra = ? WHERE token = ?`

	result, err := s.db.Exec(query, token.TokenType, token.ClientID, token.UserID,
		string(scopesJSON), string(audienceJSON), token.IssuedAt, token.ExpiresAt,
		token.Active, string(extraJSON), token.Token)

	if err != nil {
		log.Printf("SQLiteStorage: Failed to update token: %v", err)
		return fmt.Errorf("failed to update token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Token not found for update: %s", token.Token)
		return fmt.Errorf("token not found: %s", token.Token)
	}

	log.Printf("SQLiteStorage: Token updated successfully, active: %t", token.Active)
	return nil
}

func (s *SQLiteStorage) DeleteToken(token string) error {
	log.Printf("SQLiteStorage: Deleting token: %s", token)

	result, err := s.db.Exec("DELETE FROM tokens WHERE token = ?", token)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to delete token: %v", err)
		return fmt.Errorf("failed to delete token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Token not found for deletion: %s", token)
		return fmt.Errorf("token not found: %s", token)
	}

	log.Printf("SQLiteStorage: Token deleted successfully: %s", token)
	return nil
}

// Session methods
func (s *SQLiteStorage) StoreSession(session *SessionState) error {
	log.Printf("SQLiteStorage: Storing session: %s for user: %s", session.SessionID, session.UserID)

	query := `INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`

	_, err := s.db.Exec(query, session.SessionID, session.UserID, session.ExpiresAt, session.CreatedAt)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to store session: %v", err)
		return fmt.Errorf("failed to store session: %w", err)
	}

	log.Printf("SQLiteStorage: Session stored successfully: %s", session.SessionID)
	return nil
}

func (s *SQLiteStorage) GetSession(sessionID string) (*SessionState, error) {
	log.Printf("SQLiteStorage: Retrieving session: %s", sessionID)

	query := `SELECT session_id, user_id, expires_at, created_at FROM sessions WHERE session_id = ?`

	row := s.db.QueryRow(query, sessionID)

	var session SessionState

	err := row.Scan(&session.SessionID, &session.UserID, &session.ExpiresAt, &session.CreatedAt)
	if err == sql.ErrNoRows {
		log.Printf("SQLiteStorage: Session not found: %s", sessionID)
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if err != nil {
		log.Printf("SQLiteStorage: Database error retrieving session: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	session.Active = time.Now().Before(session.ExpiresAt)

	log.Printf("SQLiteStorage: Session retrieved successfully for user: %s", session.UserID)
	return &session, nil
}

func (s *SQLiteStorage) DeleteSession(sessionID string) error {
	log.Printf("SQLiteStorage: Deleting session: %s", sessionID)

	result, err := s.db.Exec("DELETE FROM sessions WHERE session_id = ?", sessionID)
	if err != nil {
		log.Printf("SQLiteStorage: Failed to delete session: %v", err)
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("SQLiteStorage: Session not found for deletion: %s", sessionID)
		return fmt.Errorf("session not found: %s", sessionID)
	}

	log.Printf("SQLiteStorage: Session deleted successfully: %s", sessionID)
	return nil
}

// CleanupExpired removes expired entries
func (s *SQLiteStorage) CleanupExpired() error {
	log.Println("SQLiteStorage: Starting cleanup of expired entries...")

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
		query := fmt.Sprintf("DELETE FROM %s WHERE %s < datetime('now')", t.table, t.column)
		result, err := s.db.Exec(query)
		if err != nil {
			log.Printf("SQLiteStorage: Failed to cleanup %s: %v", t.table, err)
			continue
		}

		if deleted, _ := result.RowsAffected(); deleted > 0 {
			log.Printf("SQLiteStorage: Cleaned up %d expired entries from %s", deleted, t.table)
			totalDeleted += int(deleted)
		}
	}

	log.Printf("SQLiteStorage: Cleanup completed, total entries removed: %d", totalDeleted)
	return nil
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	log.Printf("NewSQLiteStorage: Creating SQLite storage with database path: %s", dbPath)

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		log.Printf("NewSQLiteStorage: Ensuring directory exists: %s", dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("NewSQLiteStorage: Failed to create directory %s: %v", dir, err)
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		log.Printf("NewSQLiteStorage: Directory created successfully: %s", dir)
	}

	log.Println("NewSQLiteStorage: Opening SQLite database connection...")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("NewSQLiteStorage: Failed to open SQLite database: %v", err)
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	log.Println("NewSQLiteStorage: Testing database connection...")
	if err := db.Ping(); err != nil {
		log.Printf("NewSQLiteStorage: Failed to ping SQLite database: %v", err)
		db.Close()
		return nil, fmt.Errorf("failed to ping SQLite database: %w", err)
	}
	log.Println("NewSQLiteStorage: Database connection test successful")

	// Enable WAL mode for better concurrent access
	log.Println("NewSQLiteStorage: Enabling WAL mode for better concurrent access...")
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Printf("NewSQLiteStorage: Warning - failed to enable WAL mode: %v", err)
	} else {
		log.Println("NewSQLiteStorage: WAL mode enabled successfully")
	}

	// Enable foreign key constraints
	log.Println("NewSQLiteStorage: Enabling foreign key constraints...")
	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		log.Printf("NewSQLiteStorage: Warning - failed to enable foreign keys: %v", err)
	} else {
		log.Println("NewSQLiteStorage: Foreign key constraints enabled successfully")
	}

	log.Println("NewSQLiteStorage: Creating base SQL storage...")
	baseStorage, err := NewBaseSQLStorage(db, &SQLiteDialect{})
	if err != nil {
		log.Printf("NewSQLiteStorage: Failed to create base SQL storage: %v", err)
		db.Close()
		return nil, fmt.Errorf("failed to create base SQL storage: %w", err)
	}
	log.Println("NewSQLiteStorage: Base SQL storage created successfully")

	storage := &SQLiteStorage{
		BaseSQLStorage: baseStorage,
		dbPath:         dbPath,
	}
	log.Printf("NewSQLiteStorage: SQLite storage created successfully with path: %s", dbPath)
	return storage, nil
}

// Close closes the SQLite database connection
func (s *SQLiteStorage) Close() error {
	log.Printf("SQLiteStorage: Closing SQLite database connection for: %s", s.dbPath)
	err := s.BaseSQLStorage.Close()
	if err != nil {
		log.Printf("SQLiteStorage: Failed to close database connection: %v", err)
		return err
	}
	log.Println("SQLiteStorage: Database connection closed successfully")
	return nil
}
