package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"oauth2-server/internal/config"
)

// SQLDialect defines the interface for SQL-specific operations
type SQLDialect interface {
	// Schema methods
	GetCreateTableStatements() []string
	GetIndexStatements() []string

	// Parameter placeholder methods
	Placeholder(n int) string // Returns $1, $2 for Postgres or ?, ? for SQLite

	// SQL-specific operations
	GetTimestampFunction() string // CURRENT_TIMESTAMP vs NOW()
	GetJSONType() string          // JSONB vs TEXT
	GetExpiredCleanupQuery(table, timeColumn string) string
}

// BaseSQLStorage provides common SQL operations for both SQLite and PostgreSQL
type BaseSQLStorage struct {
	db      *sql.DB
	dialect SQLDialect
}

// NewBaseSQLStorage creates a new base SQL storage instance
func NewBaseSQLStorage(db *sql.DB, dialect SQLDialect) (*BaseSQLStorage, error) {
	storage := &BaseSQLStorage{
		db:      db,
		dialect: dialect,
	}

	if err := storage.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return storage, nil
}

// migrate creates the necessary tables and indexes
func (s *BaseSQLStorage) migrate() error {
	// Create tables
	for _, statement := range s.dialect.GetCreateTableStatements() {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("failed to execute create table statement: %w", err)
		}
	}

	// Create indexes
	for _, statement := range s.dialect.GetIndexStatements() {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("failed to execute index statement: %w", err)
		}
	}

	return nil
}

// Authorization codes methods
func (s *BaseSQLStorage) StoreAuthCode(authReq *AuthCodeState) error {
	log.Printf("BaseSQLStorage: Storing auth code: %s", authReq.Code)

	query := fmt.Sprintf(`INSERT INTO auth_codes 
		(code, client_id, response_type, redirect_uri, scopes, state, code_challenge, code_challenge_method, created_at, expires_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3),
		s.dialect.Placeholder(4), s.dialect.Placeholder(5), s.dialect.Placeholder(6),
		s.dialect.Placeholder(7), s.dialect.Placeholder(8), s.dialect.Placeholder(9),
		s.dialect.Placeholder(10))

	scopesJSON, _ := json.Marshal(authReq.Scopes)

	_, err := s.db.Exec(query,
		authReq.Code,
		authReq.ClientID,
		authReq.ResponseType, // Now using the correct field
		authReq.RedirectURI,
		string(scopesJSON),
		authReq.State,
		authReq.CodeChallenge,
		authReq.CodeChallengeMethod,
		authReq.CreatedAt,
		authReq.ExpiresAt,
	)

	if err != nil {
		log.Printf("BaseSQLStorage: Failed to store auth code: %v", err)
		return fmt.Errorf("failed to store auth code: %w", err)
	}

	log.Printf("BaseSQLStorage: Auth code stored successfully: %s", authReq.Code)
	return nil
}

func (s *BaseSQLStorage) GetAuthCode(code string) (*AuthCodeState, error) {
	log.Printf("BaseSQLStorage: Retrieving auth code: %s", code)

	query := fmt.Sprintf(`SELECT client_id, response_type, redirect_uri, scopes, state, code_challenge, code_challenge_method, created_at, expires_at
		FROM auth_codes WHERE code = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, code)

	authReq := &AuthCodeState{Code: code}
	var scopesJSON string

	err := row.Scan(
		&authReq.ClientID,
		&authReq.ResponseType, // Now using the correct field
		&authReq.RedirectURI,
		&scopesJSON,
		&authReq.State,
		&authReq.CodeChallenge,
		&authReq.CodeChallengeMethod,
		&authReq.CreatedAt,
		&authReq.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		log.Printf("BaseSQLStorage: Auth code not found: %s", code)
		return nil, fmt.Errorf("auth code not found: %s", code)
	}
	if err != nil {
		log.Printf("BaseSQLStorage: Database error retrieving auth code: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &authReq.Scopes)
	}

	log.Printf("BaseSQLStorage: Auth code retrieved successfully: %s", code)
	return authReq, nil
}

func (s *BaseSQLStorage) DeleteAuthCode(code string) error {
	query := fmt.Sprintf("DELETE FROM auth_codes WHERE code = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, code)
	return err
}

// Device codes methods - Fixed method signature
func (s *BaseSQLStorage) StoreDeviceCode(state *DeviceCodeState) error {
	log.Printf("BaseSQLStorage: Storing device code: %s", state.DeviceCode)

	// Convert scopes slice to space-separated string for storage
	scopesStr := strings.Join(state.Scopes, " ")

	// Calculate expires_at from ExpiresIn
	expiresAt := state.CreatedAt.Add(time.Duration(state.ExpiresIn) * time.Second)

	query := fmt.Sprintf(`INSERT INTO device_codes 
		(device_code, user_code, client_id, scopes, expires_in, interval_seconds, 
		 created_at, expires_at, authorized, user_id, access_token)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3),
		s.dialect.Placeholder(4), s.dialect.Placeholder(5), s.dialect.Placeholder(6),
		s.dialect.Placeholder(7), s.dialect.Placeholder(8), s.dialect.Placeholder(9),
		s.dialect.Placeholder(10), s.dialect.Placeholder(11))

	_, err := s.db.Exec(query,
		state.DeviceCode,
		state.UserCode,
		state.ClientID,
		scopesStr,
		state.ExpiresIn,
		state.Interval,
		state.CreatedAt,
		expiresAt,
		state.Authorized,
		state.UserID,
		state.AccessToken,
	)

	if err != nil {
		log.Printf("BaseSQLStorage: Failed to store device code: %v", err)
		return fmt.Errorf("failed to store device code: %w", err)
	}

	log.Printf("BaseSQLStorage: Device code stored successfully: %s", state.DeviceCode)
	return nil
}

func (s *BaseSQLStorage) GetDeviceCode(deviceCode string) (*DeviceCodeState, error) {
	query := fmt.Sprintf(`SELECT user_code, client_id, scopes, expires_in, interval_seconds,
		created_at, expires_at, authorized, user_id, access_token
		FROM device_codes WHERE device_code = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, deviceCode)

	var scopesStr string
	var userID, accessToken sql.NullString
	var expiresAt time.Time

	state := &DeviceCodeState{
		DeviceCode: deviceCode,
	}

	err := row.Scan(
		&state.UserCode,
		&state.ClientID,
		&scopesStr,
		&state.ExpiresIn, // Map to correct struct field
		&state.Interval,  // Map to correct struct field
		&state.CreatedAt,
		&expiresAt,
		&state.Authorized,
		&userID,
		&accessToken,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device code not found")
	}
	if err != nil {
		return nil, err
	}

	// Convert space-separated scopes back to slice
	if scopesStr != "" {
		state.Scopes = strings.Fields(scopesStr)
	}

	// Set nullable fields
	state.UserID = userID.String
	state.AccessToken = accessToken.String

	return state, nil
}

func (s *BaseSQLStorage) GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, string, error) {
	query := fmt.Sprintf(`SELECT device_code, client_id, scopes, expires_in, interval_seconds,
		created_at, expires_at, authorized, user_id, access_token
		FROM device_codes WHERE user_code = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, userCode)

	var deviceCode, scopesStr string
	var userID, accessToken sql.NullString
	var expiresAt time.Time

	state := &DeviceCodeState{
		UserCode: userCode,
	}

	err := row.Scan(
		&deviceCode,
		&state.ClientID,
		&scopesStr,
		&state.ExpiresIn, // Map to correct struct field
		&state.Interval,  // Map to correct struct field
		&state.CreatedAt,
		&expiresAt,
		&state.Authorized,
		&userID,
		&accessToken,
	)

	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("device code not found for user code")
	}
	if err != nil {
		return nil, "", err
	}

	// Set the device code and convert scopes
	state.DeviceCode = deviceCode
	if scopesStr != "" {
		state.Scopes = strings.Fields(scopesStr)
	}

	// Set nullable fields
	state.UserID = userID.String
	state.AccessToken = accessToken.String

	return state, deviceCode, nil
}

func (s *BaseSQLStorage) UpdateDeviceCode(deviceCode string, state *DeviceCodeState) error {
	query := fmt.Sprintf(`UPDATE device_codes SET 
		authorized = %s, user_id = %s, access_token = %s
		WHERE device_code = %s`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2),
		s.dialect.Placeholder(3), s.dialect.Placeholder(4))

	_, err := s.db.Exec(query, state.Authorized, state.UserID, state.AccessToken, deviceCode)
	return err
}

func (s *BaseSQLStorage) DeleteDeviceCode(deviceCode string) error {
	query := fmt.Sprintf("DELETE FROM device_codes WHERE device_code = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, deviceCode)
	return err
}

// Dynamic clients methods
func (s *BaseSQLStorage) StoreDynamicClient(clientID string, client *config.ClientConfig) error {
	// Convert slices to JSON
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	responseTypes, _ := json.Marshal(client.ResponseTypes)
	scopes, _ := json.Marshal(client.Scopes)
	allowedAudiences, _ := json.Marshal(client.AllowedAudiences)
	allowedOrigins, _ := json.Marshal(client.AllowedOrigins)

	query := fmt.Sprintf(`INSERT INTO dynamic_clients 
		(client_id, client_secret, client_name, description, redirect_uris, grant_types, response_types, 
		 scopes, token_endpoint_auth_method, public, allowed_audiences, 
		 allow_token_exchange, allowed_origins, software_id, software_version, 
		 client_id_issued_at, client_secret_expires_at, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3),
		s.dialect.Placeholder(4), s.dialect.Placeholder(5), s.dialect.Placeholder(6),
		s.dialect.Placeholder(7), s.dialect.Placeholder(8), s.dialect.Placeholder(9),
		s.dialect.Placeholder(10), s.dialect.Placeholder(11), s.dialect.Placeholder(12),
		s.dialect.Placeholder(13), s.dialect.Placeholder(14), s.dialect.Placeholder(15),
		s.dialect.Placeholder(16), s.dialect.Placeholder(17), s.dialect.Placeholder(18),
		s.dialect.Placeholder(19))

	now := time.Now()
	_, err := s.db.Exec(query,
		clientID,
		client.Secret,
		client.Name,
		client.Description,
		string(redirectURIs),
		string(grantTypes),
		string(responseTypes),
		string(scopes),
		client.TokenEndpointAuthMethod,
		client.Public,
		string(allowedAudiences),
		client.AllowTokenExchange,
		string(allowedOrigins),
		"",   // software_id
		"",   // software_version
		&now, // client_id_issued_at
		nil,  // client_secret_expires_at
		&now, // created_at
		&now) // updated_at
	return err
}

func (s *BaseSQLStorage) GetDynamicClient(clientID string) (*config.ClientConfig, error) {
	query := fmt.Sprintf(`SELECT client_secret, client_name, description, redirect_uris, grant_types, response_types,
        scopes, token_endpoint_auth_method, public, allowed_audiences, allow_token_exchange, allowed_origins
        FROM dynamic_clients WHERE client_id = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, clientID)

	var redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON string
	var allowedAudiencesJSON, allowedOriginsJSON string
	var clientSecret, name, description, authMethod sql.NullString
	var public, allowTokenExchange sql.NullBool
	client := &config.ClientConfig{ID: clientID}

	err := row.Scan(
		&clientSecret,
		&name,
		&description,
		&redirectURIsJSON,
		&grantTypesJSON,
		&responseTypesJSON,
		&scopesJSON,
		&authMethod,
		&public,
		&allowedAudiencesJSON,
		&allowTokenExchange,
		&allowedOriginsJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Set basic fields
	client.Secret = clientSecret.String
	client.Name = name.String
	client.Description = description.String
	client.TokenEndpointAuthMethod = authMethod.String
	client.Public = public.Bool
	client.AllowTokenExchange = allowTokenExchange.Bool

	// Parse JSON arrays
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
	if allowedAudiencesJSON != "" {
		json.Unmarshal([]byte(allowedAudiencesJSON), &client.AllowedAudiences)
	}
	if allowedOriginsJSON != "" {
		json.Unmarshal([]byte(allowedOriginsJSON), &client.AllowedOrigins)
	}

	return client, nil
}

func (s *BaseSQLStorage) DeleteDynamicClient(clientID string) error {
	query := fmt.Sprintf("DELETE FROM dynamic_clients WHERE client_id = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, clientID)
	return err
}

// Registration tokens methods
func (s *BaseSQLStorage) StoreRegistrationToken(token, clientID string) error {
	now := time.Now()
	// Registration tokens typically expire after 24 hours
	expiresAt := now.Add(24 * time.Hour)

	query := fmt.Sprintf("INSERT INTO registration_tokens (token, client_id, created_at, expires_at) VALUES (%s, %s, %s, %s)",
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3), s.dialect.Placeholder(4))
	_, err := s.db.Exec(query, token, clientID, now, expiresAt)
	return err
}

func (s *BaseSQLStorage) GetClientIDByRegistrationToken(token string) (string, error) {
	query := fmt.Sprintf("SELECT client_id FROM registration_tokens WHERE token = %s", s.dialect.Placeholder(1))

	var clientID string
	err := s.db.QueryRow(query, token).Scan(&clientID)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return clientID, nil
}

func (s *BaseSQLStorage) DeleteRegistrationToken(token string) error {
	query := fmt.Sprintf("DELETE FROM registration_tokens WHERE token = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, token)
	return err
}

// OAuth2 Tokens methods - Fixed to use all TokenState fields
func (s *BaseSQLStorage) StoreToken(tokenInfo *TokenState) error {
	log.Printf("BaseSQLStorage: Storing token: %s", tokenInfo.TokenType)

	// Convert arrays and maps to JSON
	scopesJSON, _ := json.Marshal(tokenInfo.Scopes)
	audienceJSON, _ := json.Marshal(tokenInfo.Audience)
	extraJSON, _ := json.Marshal(tokenInfo.Extra)

	query := fmt.Sprintf(`INSERT INTO tokens 
		(token, token_type, client_id, user_id, scopes, audience, subject, issued_at, expires_at, 
		 not_before, active, extra, parent_access_token, nonce, auth_time, grant_type, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3),
		s.dialect.Placeholder(4), s.dialect.Placeholder(5), s.dialect.Placeholder(6),
		s.dialect.Placeholder(7), s.dialect.Placeholder(8), s.dialect.Placeholder(9),
		s.dialect.Placeholder(10), s.dialect.Placeholder(11), s.dialect.Placeholder(12),
		s.dialect.Placeholder(13), s.dialect.Placeholder(14), s.dialect.Placeholder(15),
		s.dialect.Placeholder(16), s.dialect.Placeholder(17))

	_, err := s.db.Exec(query,
		tokenInfo.Token,
		tokenInfo.TokenType,
		tokenInfo.ClientID,
		tokenInfo.UserID,
		string(scopesJSON),
		string(audienceJSON),
		tokenInfo.Subject, // Now available
		tokenInfo.IssuedAt,
		tokenInfo.ExpiresAt,
		tokenInfo.NotBefore, // Now available
		tokenInfo.Active,
		string(extraJSON),
		tokenInfo.ParentAccessToken, // Now available
		tokenInfo.Nonce,             // Now available
		tokenInfo.AuthTime,          // Now available
		tokenInfo.GrantType,         // Now available
		tokenInfo.CreatedAt,
	)

	if err != nil {
		log.Printf("BaseSQLStorage: Failed to store token: %v", err)
		return fmt.Errorf("failed to store token: %w", err)
	}

	log.Printf("BaseSQLStorage: Token stored successfully: %s", tokenInfo.TokenType)
	return nil
}

func (s *BaseSQLStorage) GetToken(token string) (*TokenInfo, error) {
	query := fmt.Sprintf(`SELECT token_type, client_id, user_id, scopes, audience, 
        issued_at, expires_at, active, extra FROM tokens WHERE token = %s`,
		s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, token)

	var tokenInfo TokenInfo
	var scopesJSON, audienceJSON, extraJSON string
	var issuedAt, expiresAt time.Time

	err := row.Scan(
		&tokenInfo.TokenType,
		&tokenInfo.ClientID,
		&tokenInfo.UserID,
		&scopesJSON,
		&audienceJSON,
		&issuedAt,
		&expiresAt,
		&tokenInfo.Active,
		&extraJSON,
	)

	// This is the critical part - return proper errors!
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("token not found") // Return error, not (nil, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse JSON fields
	if scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &tokenInfo.Scopes)
	}
	if audienceJSON != "" {
		json.Unmarshal([]byte(audienceJSON), &tokenInfo.Audience)
	}
	if extraJSON != "" {
		json.Unmarshal([]byte(extraJSON), &tokenInfo.Extra)
	}

	tokenInfo.Token = token
	tokenInfo.IssuedAt = issuedAt
	tokenInfo.ExpiresAt = expiresAt

	return &tokenInfo, nil // Return valid token info with no error
}

func (s *BaseSQLStorage) GetTokensByClientID(clientID string) ([]*TokenInfo, error) {
	query := fmt.Sprintf(`SELECT token, token_type, user_id, scopes, audience, subject, issued_at, expires_at,
		not_before, active, extra, parent_access_token, nonce, auth_time, grant_type, created_at
		FROM tokens WHERE client_id = %s AND active = TRUE ORDER BY created_at DESC`, s.dialect.Placeholder(1))

	return s.getTokensFromQuery(query, clientID)
}

func (s *BaseSQLStorage) GetTokensByUserID(userID string) ([]*TokenInfo, error) {
	query := fmt.Sprintf(`SELECT token, token_type, client_id, scopes, audience, subject, issued_at, expires_at,
		not_before, active, extra, parent_access_token, nonce, auth_time, grant_type, created_at
		FROM tokens WHERE user_id = %s AND active = TRUE ORDER BY created_at DESC`, s.dialect.Placeholder(1))

	return s.getTokensFromQuery(query, userID)
}

func (s *BaseSQLStorage) getTokensFromQuery(query string, param interface{}) ([]*TokenInfo, error) {
	rows, err := s.db.Query(query, param)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*TokenInfo
	for rows.Next() {
		var audienceJSON, extraJSON string
		var userID, clientID, scopes, subject, parentAccessToken, nonce, grantType sql.NullString
		var notBefore, authTime sql.NullTime
		tokenInfo := &TokenInfo{}

		err := rows.Scan(
			&tokenInfo.Token,
			&tokenInfo.TokenType,
			&clientID, // Could be userID depending on query
			&scopes,
			&audienceJSON,
			&subject,
			&tokenInfo.IssuedAt,
			&tokenInfo.ExpiresAt,
			&notBefore,
			&tokenInfo.Active,
			&extraJSON,
			&parentAccessToken,
			&nonce,
			&authTime,
			&grantType,
			&tokenInfo.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Set fields (logic depends on which query was called)
		tokenInfo.ClientID = clientID.String
		tokenInfo.UserID = userID.String
		tokenInfo.Scopes = strings.Fields(scopes.String)
		tokenInfo.Subject = subject.String
		tokenInfo.ParentAccessToken = parentAccessToken.String
		tokenInfo.Nonce = nonce.String
		tokenInfo.GrantType = grantType.String

		if notBefore.Valid {
			tokenInfo.NotBefore = notBefore.Time
		}
		if authTime.Valid {
			tokenInfo.AuthTime = &authTime.Time
		}

		// Parse JSON fields
		if audienceJSON != "" {
			json.Unmarshal([]byte(audienceJSON), &tokenInfo.Audience)
		}
		if extraJSON != "" {
			json.Unmarshal([]byte(extraJSON), &tokenInfo.Extra)
		}

		tokens = append(tokens, tokenInfo)
	}

	return tokens, rows.Err()
}

func (s *BaseSQLStorage) UpdateTokenStatus(token string, active bool) error {
	query := fmt.Sprintf("UPDATE tokens SET active = %s WHERE token = %s",
		s.dialect.Placeholder(1), s.dialect.Placeholder(2))
	_, err := s.db.Exec(query, active, token)
	return err
}

func (s *BaseSQLStorage) DeleteToken(token string) error {
	query := fmt.Sprintf("DELETE FROM tokens WHERE token = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, token)
	return err
}

func (s *BaseSQLStorage) DeleteTokensByClientID(clientID string) error {
	query := fmt.Sprintf("DELETE FROM tokens WHERE client_id = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, clientID)
	return err
}

func (s *BaseSQLStorage) DeleteTokensByUserID(userID string) error {
	query := fmt.Sprintf("DELETE FROM tokens WHERE user_id = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, userID)
	return err
}

// CleanupExpired removes expired entries
func (s *BaseSQLStorage) CleanupExpired() error {
	tables := []struct {
		table      string
		timeColumn string
	}{
		{"auth_codes", "expires_at"},
		{"device_codes", "expires_at"},
		{"tokens", "expires_at"},
	}

	for _, t := range tables {
		query := s.dialect.GetExpiredCleanupQuery(t.table, t.timeColumn)
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to cleanup expired entries from %s: %w", t.table, err)
		}
	}

	return nil
}

// Close closes the database connection
func (s *BaseSQLStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// In your SQL storage implementation, add these no-op methods:

func (s *BaseSQLStorage) StoreSession(sessionID, userID string) error {
	// Sessions are not persisted in SQL - this is a no-op
	return fmt.Errorf("sessions not supported in SQL storage")
}

func (s *BaseSQLStorage) GetSession(sessionID string) (*Session, error) {
	// Sessions are not persisted in SQL - this is a no-op
	return nil, fmt.Errorf("sessions not supported in SQL storage")
}

func (s *BaseSQLStorage) DeleteSession(sessionID string) error {
	// Sessions are not persisted in SQL - this is a no-op
	return fmt.Errorf("sessions not supported in SQL storage")
}
