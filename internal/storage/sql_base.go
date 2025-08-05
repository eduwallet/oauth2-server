package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"oauth2-demo/internal/config"
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
func (s *BaseSQLStorage) StoreAuthCode(code string, authReq *AuthorizeRequest) error {
	query := fmt.Sprintf(`INSERT INTO auth_codes 
		(code, client_id, response_type, redirect_uri, scope, state, code_challenge, code_challenge_method, created_at, expires_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3),
		s.dialect.Placeholder(4), s.dialect.Placeholder(5), s.dialect.Placeholder(6),
		s.dialect.Placeholder(7), s.dialect.Placeholder(8), s.dialect.Placeholder(9),
		s.dialect.Placeholder(10))

	_, err := s.db.Exec(query,
		code,
		authReq.ClientID,
		authReq.ResponseType,
		authReq.RedirectURI,
		authReq.Scope,
		authReq.State,
		authReq.CodeChallenge,
		authReq.CodeChallengeMethod,
		authReq.CreatedAt,
		authReq.ExpiresAt,
	)
	return err
}

func (s *BaseSQLStorage) GetAuthCode(code string) (*AuthorizeRequest, error) {
	query := fmt.Sprintf(`SELECT client_id, response_type, redirect_uri, scope, state, code_challenge, code_challenge_method, created_at, expires_at
		FROM auth_codes WHERE code = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, code)

	authReq := &AuthorizeRequest{}
	err := row.Scan(
		&authReq.ClientID,
		&authReq.ResponseType,
		&authReq.RedirectURI,
		&authReq.Scope,
		&authReq.State,
		&authReq.CodeChallenge,
		&authReq.CodeChallengeMethod,
		&authReq.CreatedAt,
		&authReq.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return authReq, nil
}

func (s *BaseSQLStorage) DeleteAuthCode(code string) error {
	query := fmt.Sprintf("DELETE FROM auth_codes WHERE code = %s", s.dialect.Placeholder(1))
	_, err := s.db.Exec(query, code)
	return err
}

// Device codes methods
func (s *BaseSQLStorage) StoreDeviceCode(deviceCode string, state *DeviceCodeState) error {
	query := fmt.Sprintf(`INSERT INTO device_codes 
		(device_code, user_code, client_id, scope, verification_uri, verification_uri_complete, 
		 expires_in, interval, created_at, expires_at, authorized, user_id, access_token)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3),
		s.dialect.Placeholder(4), s.dialect.Placeholder(5), s.dialect.Placeholder(6),
		s.dialect.Placeholder(7), s.dialect.Placeholder(8), s.dialect.Placeholder(9),
		s.dialect.Placeholder(10), s.dialect.Placeholder(11), s.dialect.Placeholder(12),
		s.dialect.Placeholder(13))

	_, err := s.db.Exec(query,
		deviceCode,
		state.UserCode,
		state.ClientID,
		state.Scope,
		state.VerificationURI,
		state.VerificationURIComplete,
		state.ExpiresIn,
		state.Interval,
		state.CreatedAt,
		state.ExpiresAt,
		state.Authorized,
		state.UserID,
		state.AccessToken,
	)
	return err
}

func (s *BaseSQLStorage) GetDeviceCode(deviceCode string) (*DeviceCodeState, error) {
	query := fmt.Sprintf(`SELECT user_code, client_id, scope, verification_uri, verification_uri_complete,
		expires_in, interval, created_at, expires_at, authorized, user_id, access_token
		FROM device_codes WHERE device_code = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, deviceCode)

	state := &DeviceCodeState{
		DeviceCodeResponse: &DeviceCodeResponse{
			DeviceCode: deviceCode,
		},
	}

	err := row.Scan(
		&state.UserCode,
		&state.ClientID,
		&state.Scope,
		&state.VerificationURI,
		&state.VerificationURIComplete,
		&state.ExpiresIn,
		&state.Interval,
		&state.CreatedAt,
		&state.ExpiresAt,
		&state.Authorized,
		&state.UserID,
		&state.AccessToken,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return state, nil
}

func (s *BaseSQLStorage) GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, string, error) {
	query := fmt.Sprintf(`SELECT device_code, client_id, scope, verification_uri, verification_uri_complete,
		expires_in, interval, created_at, expires_at, authorized, user_id, access_token
		FROM device_codes WHERE user_code = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, userCode)

	var deviceCode string
	state := &DeviceCodeState{
		DeviceCodeResponse: &DeviceCodeResponse{
			UserCode: userCode,
		},
	}

	err := row.Scan(
		&deviceCode,
		&state.ClientID,
		&state.Scope,
		&state.VerificationURI,
		&state.VerificationURIComplete,
		&state.ExpiresIn,
		&state.Interval,
		&state.CreatedAt,
		&state.ExpiresAt,
		&state.Authorized,
		&state.UserID,
		&state.AccessToken,
	)

	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}

	state.DeviceCode = deviceCode
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
	audience, _ := json.Marshal(client.Audience)
	enabledFlows, _ := json.Marshal(client.EnabledFlows)

	query := fmt.Sprintf(`INSERT INTO dynamic_clients 
		(client_id, client_secret, client_name, description, redirect_uris, grant_types, response_types, 
		 scope, audience, token_endpoint_auth_method, public, enabled_flows, software_id, software_version, 
		 client_id_issued_at, client_secret_expires_at, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)`,
		s.dialect.Placeholder(1), s.dialect.Placeholder(2), s.dialect.Placeholder(3),
		s.dialect.Placeholder(4), s.dialect.Placeholder(5), s.dialect.Placeholder(6),
		s.dialect.Placeholder(7), s.dialect.Placeholder(8), s.dialect.Placeholder(9),
		s.dialect.Placeholder(10), s.dialect.Placeholder(11), s.dialect.Placeholder(12),
		s.dialect.Placeholder(13), s.dialect.Placeholder(14), s.dialect.Placeholder(15),
		s.dialect.Placeholder(16), s.dialect.Placeholder(17), s.dialect.Placeholder(18))

	now := time.Now()
	_, err := s.db.Exec(query, clientID, client.Secret, client.Name, client.Description,
		string(redirectURIs), string(grantTypes), string(responseTypes), string(scopes),
		string(audience), client.TokenEndpointAuthMethod, client.Public, string(enabledFlows),
		"", "", &now, nil, &now, &now) // software_id, software_version, issued_at, expires_at, created_at, updated_at
	return err
}

func (s *BaseSQLStorage) GetDynamicClient(clientID string) (*config.ClientConfig, error) {
	query := fmt.Sprintf(`SELECT client_secret, client_name, description, redirect_uris, grant_types, response_types,
		scope, audience, token_endpoint_auth_method, public, enabled_flows
		FROM dynamic_clients WHERE client_id = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, clientID)

	var redirectURIsJSON, grantTypesJSON, responseTypesJSON, scopesJSON, audienceJSON, enabledFlowsJSON string
	var clientSecret, name, description, authMethod sql.NullString
	var public sql.NullBool
	client := &config.ClientConfig{ID: clientID}

	err := row.Scan(
		&clientSecret,
		&name,
		&description,
		&redirectURIsJSON,
		&grantTypesJSON,
		&responseTypesJSON,
		&scopesJSON,
		&audienceJSON,
		&authMethod,
		&public,
		&enabledFlowsJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	client.Secret = clientSecret.String
	client.Name = name.String
	client.Description = description.String
	client.TokenEndpointAuthMethod = authMethod.String
	client.Public = public.Bool

	// Parse JSON arrays
	json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs)
	json.Unmarshal([]byte(grantTypesJSON), &client.GrantTypes)
	json.Unmarshal([]byte(responseTypesJSON), &client.ResponseTypes)
	json.Unmarshal([]byte(scopesJSON), &client.Scopes)
	json.Unmarshal([]byte(audienceJSON), &client.Audience)
	json.Unmarshal([]byte(enabledFlowsJSON), &client.EnabledFlows)

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

// OAuth2 Tokens methods
func (s *BaseSQLStorage) StoreToken(tokenInfo *TokenInfo) error {
	// Convert arrays and maps to JSON
	audienceJSON, _ := json.Marshal(tokenInfo.Audience)
	extraJSON, _ := json.Marshal(tokenInfo.Extra)

	query := fmt.Sprintf(`INSERT INTO tokens 
		(token, token_type, client_id, user_id, scope, audience, subject, issued_at, expires_at, 
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
		tokenInfo.Scope,
		string(audienceJSON),
		tokenInfo.Subject,
		tokenInfo.IssuedAt,
		tokenInfo.ExpiresAt,
		tokenInfo.NotBefore,
		tokenInfo.Active,
		string(extraJSON),
		tokenInfo.ParentAccessToken,
		tokenInfo.Nonce,
		tokenInfo.AuthTime,
		tokenInfo.GrantType,
		tokenInfo.CreatedAt,
	)
	return err
}

func (s *BaseSQLStorage) GetToken(token string) (*TokenInfo, error) {
	query := fmt.Sprintf(`SELECT token_type, client_id, user_id, scope, audience, subject, issued_at, expires_at,
		not_before, active, extra, parent_access_token, nonce, auth_time, grant_type, created_at
		FROM tokens WHERE token = %s`, s.dialect.Placeholder(1))

	row := s.db.QueryRow(query, token)

	var audienceJSON, extraJSON string
	var userID, scope, subject, parentAccessToken, nonce, grantType sql.NullString
	var notBefore, authTime sql.NullTime
	tokenInfo := &TokenInfo{Token: token}

	err := row.Scan(
		&tokenInfo.TokenType,
		&tokenInfo.ClientID,
		&userID,
		&scope,
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

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Set nullable fields
	tokenInfo.UserID = userID.String
	tokenInfo.Scope = scope.String
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

	return tokenInfo, nil
}

func (s *BaseSQLStorage) GetTokensByClientID(clientID string) ([]*TokenInfo, error) {
	query := fmt.Sprintf(`SELECT token, token_type, user_id, scope, audience, subject, issued_at, expires_at,
		not_before, active, extra, parent_access_token, nonce, auth_time, grant_type, created_at
		FROM tokens WHERE client_id = %s AND active = TRUE ORDER BY created_at DESC`, s.dialect.Placeholder(1))

	return s.getTokensFromQuery(query, clientID)
}

func (s *BaseSQLStorage) GetTokensByUserID(userID string) ([]*TokenInfo, error) {
	query := fmt.Sprintf(`SELECT token, token_type, client_id, scope, audience, subject, issued_at, expires_at,
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
		var userID, clientID, scope, subject, parentAccessToken, nonce, grantType sql.NullString
		var notBefore, authTime sql.NullTime
		tokenInfo := &TokenInfo{}

		err := rows.Scan(
			&tokenInfo.Token,
			&tokenInfo.TokenType,
			&clientID, // Could be userID depending on query
			&scope,
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
		tokenInfo.Scope = scope.String
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
