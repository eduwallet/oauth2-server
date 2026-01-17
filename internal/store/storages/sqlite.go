package storages

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"oauth2-server/internal/store/types"
	"oauth2-server/pkg/config"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

// SQLiteStore implements Fosite storage interfaces using SQLite
type SQLiteStore struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewSQLiteStore creates a new SQLite store
func NewSQLiteStore(dbPath string, logger *logrus.Logger) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	store := &SQLiteStore{
		db:     db,
		logger: logger,
	}

	if err := store.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return store, nil
}

// initTables creates the necessary database tables
func (s *SQLiteStore) initTables() error {
	queries := []string{
		// Clients table
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			encrypted_secret TEXT,
			attestation_config TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Access tokens table
		`CREATE TABLE IF NOT EXISTS access_tokens (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Refresh tokens table
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Authorization codes table
		`CREATE TABLE IF NOT EXISTS authorization_codes (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// PKCE table
		`CREATE TABLE IF NOT EXISTS pkce (
			signature TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Client assertion JWT table
		`CREATE TABLE IF NOT EXISTS client_assertion_jwt (
			jti TEXT PRIMARY KEY,
			expires_at DATETIME NOT NULL
		)`,

		// Device codes table
		`CREATE TABLE IF NOT EXISTS device_codes (
			signature TEXT PRIMARY KEY,
			user_code TEXT,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Trust anchors table
		`CREATE TABLE IF NOT EXISTS trust_anchors (
			name TEXT PRIMARY KEY,
			certificate_data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Upstream token mappings table for proxy mode
		`CREATE TABLE IF NOT EXISTS upstream_token_mappings (
			proxy_token_signature TEXT PRIMARY KEY,
			upstream_access_token TEXT NOT NULL,
			upstream_refresh_token TEXT,
			upstream_token_type TEXT NOT NULL DEFAULT 'bearer',
			upstream_expires_in INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// PAR (Pushed Authorization Request) table
		`CREATE TABLE IF NOT EXISTS par_requests (
			request_uri TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			parameters TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %q: %w", query, err)
		}
	}

	s.logger.Info("✅ SQLite tables initialized")
	return nil
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Client storage methods
func (s *SQLiteStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM clients WHERE id = ?", id).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidClient
	}
	if err != nil {
		return nil, err
	}

	// Try to unmarshal into CustomClient first to preserve CIMD fields if present
	var customClient types.CustomClient
	if err := json.Unmarshal([]byte(data), &customClient); err == nil {
		if customClient.DefaultClient == nil {
			// If DefaultClient wasn't embedded properly, fall back
			var dc fosite.DefaultClient
			if err := json.Unmarshal([]byte(data), &dc); err != nil {
				return nil, err
			}
			return &dc, nil
		}
		return &customClient, nil
	}

	// Fallback to default client
	var client fosite.DefaultClient
	if err := json.Unmarshal([]byte(data), &client); err != nil {
		return nil, err
	}

	return &client, nil
}

func (s *SQLiteStore) GetAllClients(ctx context.Context) ([]fosite.Client, error) {
	rows, err := s.db.Query("SELECT data FROM clients")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []fosite.Client
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}

		// Try custom client first
		var customClient types.CustomClient
		if err := json.Unmarshal([]byte(data), &customClient); err == nil {
			if customClient.DefaultClient != nil {
				clients = append(clients, &customClient)
				continue
			}
		}

		var client fosite.DefaultClient
		if err := json.Unmarshal([]byte(data), &client); err != nil {
			return nil, err
		}

		clients = append(clients, &client)
	}

	return clients, nil
}

func (s *SQLiteStore) CreateClient(ctx context.Context, client fosite.Client) error {
	data, err := json.Marshal(client)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO clients (id, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
		client.GetID(), string(data),
	)
	return err
}

func (s *SQLiteStore) UpdateClient(ctx context.Context, id string, client fosite.Client) error {
	return s.CreateClient(ctx, client)
}

func (s *SQLiteStore) DeleteClient(ctx context.Context, id string) error {
	_, err := s.db.Exec("DELETE FROM clients WHERE id = ?", id)
	return err
}

// User storage methods (for local mode)
func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*storage.MemoryUserRelation, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM users WHERE id = ?", id).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	var user storage.MemoryUserRelation
	if err := json.Unmarshal([]byte(data), &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *SQLiteStore) CreateUser(ctx context.Context, id string, user *storage.MemoryUserRelation) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO users (id, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
		id, string(data),
	)
	return err
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, id string, user *storage.MemoryUserRelation) error {
	return s.CreateUser(ctx, id, user)
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// Token storage methods
func (s *SQLiteStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	data, err := types.MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO access_tokens (signature, data) VALUES (?, ?)",
		signature, string(data),
	)
	return err
}

func (s *SQLiteStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM access_tokens WHERE signature = ?", signature).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	request, err := s.UnmarshalRequestWithClientID([]byte(data))
	if err != nil {
		return nil, err
	}

	// Ensure session is never nil to avoid downstream panics
	if request != nil && request.GetSession() == nil {
		switch r := request.(type) {
		case *fosite.AccessRequest:
			r.Session = &openid.DefaultSession{}
		case *fosite.Request:
			r.Session = &openid.DefaultSession{}
		}
	}

	// Ensure access token expiry is set; some stored sessions may have zero-value expiry
	if sess := request.GetSession(); sess != nil {
		if sess.GetExpiresAt(fosite.AccessToken).IsZero() {
			sess.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(1*time.Hour))
		}
	}

	return request, nil
}

func (s *SQLiteStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.Exec("DELETE FROM access_tokens WHERE signature = ?", signature)
	return err
}

func (s *SQLiteStore) CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, request fosite.Requester) error {
	data, err := types.MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO refresh_tokens (signature, data) VALUES (?, ?)",
		signature, string(data),
	)
	return err
}

func (s *SQLiteStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM refresh_tokens WHERE signature = ?", signature).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	request, err := s.UnmarshalRequestWithClientID([]byte(data))
	if err != nil {
		return nil, err
	}

	// Ensure session is never nil to avoid downstream panics
	if request != nil && request.GetSession() == nil {
		switch r := request.(type) {
		case *fosite.AccessRequest:
			r.Session = &openid.DefaultSession{}
		case *fosite.Request:
			r.Session = &openid.DefaultSession{}
		}
	}

	// Ensure refresh token expiry is set; some stored sessions may have zero-value expiry
	if sess := request.GetSession(); sess != nil {
		if sess.GetExpiresAt(fosite.RefreshToken).IsZero() {
			sess.SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(24*time.Hour))
		}
	}

	return request, nil
}

func (s *SQLiteStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.Exec("DELETE FROM refresh_tokens WHERE signature = ?", signature)
	return err
}

func (s *SQLiteStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	// For basic implementation, we don't rotate refresh tokens
	// This could be implemented to update the refresh token signature for security
	return nil
}

func (s *SQLiteStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	// For basic implementation, we don't revoke access tokens by request ID
	// This could be implemented to revoke all access tokens for a specific request
	return nil
}

func (s *SQLiteStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	// For basic implementation, we don't revoke refresh tokens by request ID
	// This could be implemented to revoke all refresh tokens for a specific request
	return nil
}

func (s *SQLiteStore) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	data, err := types.MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	s.logger.Debugf("🔍 SQLiteStore.CreateAuthorizeCodeSession: storing JSON: %s", string(data))

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO authorization_codes (signature, data) VALUES (?, ?)",
		code, string(data),
	)
	return err
}

func (s *SQLiteStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM authorization_codes WHERE signature = ?", code).Scan(&data)
	if err == sql.ErrNoRows {
		// If not found, try extracting the signature part (after the last dot)
		parts := strings.Split(code, ".")
		if len(parts) > 1 {
			signature := parts[len(parts)-1]
			s.logger.Debugf("🔍 SQLiteStore.GetAuthorizeCodeSession: trying signature part: %s", signature)
			err = s.db.QueryRow("SELECT data FROM authorization_codes WHERE signature = ?", signature).Scan(&data)
		}
	}

	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	s.logger.Debugf("🔍 SQLiteStore.GetAuthorizeCodeSession: unmarshaling JSON: %s", data)
	request, err := s.UnmarshalRequestWithClientID([]byte(data))
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.GetAuthorizeCodeSession: unmarshal error: %v", err)
		return nil, err
	}

	s.logger.Debugf("✅ SQLiteStore.GetAuthorizeCodeSession: successfully unmarshaled request with client: %T, ID: %s", request.GetClient(), request.GetClient().GetID())
	return request, nil
}

func (s *SQLiteStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	_, err := s.db.Exec("DELETE FROM authorization_codes WHERE signature = ?", code)
	return err
}

// PKCE methods
func (s *SQLiteStore) CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error {
	data, err := types.MarshalRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO pkce (signature, data) VALUES (?, ?)",
		code, string(data),
	)
	return err
}

func (s *SQLiteStore) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM pkce WHERE signature = ?", code).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		return nil, err
	}

	return s.UnmarshalRequestWithClientID([]byte(data))
}

func (s *SQLiteStore) DeletePKCERequestSession(ctx context.Context, code string) error {
	_, err := s.db.Exec("DELETE FROM pkce WHERE signature = ?", code)
	return err
}

// Client Assertion JWT methods
func (s *SQLiteStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var expiresAt time.Time
	err := s.db.QueryRow("SELECT expires_at FROM client_assertion_jwt WHERE jti = ?", jti).Scan(&expiresAt)
	if err == sql.ErrNoRows {
		return fosite.ErrInvalidRequest
	}
	if err != nil {
		return err
	}

	if time.Now().After(expiresAt) {
		return fosite.ErrInvalidRequest
	}

	return nil
}

func (s *SQLiteStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO client_assertion_jwt (jti, expires_at) VALUES (?, ?)",
		jti, exp,
	)
	return err
}

// Device authorization methods
func (s *SQLiteStore) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.DeviceRequester, error) {
	s.logger.Debugf("🔍 SQLiteStore.GetDeviceCodeSession: looking for device code: %s", deviceCode)

	// Try the full device code first
	var data string
	err := s.db.QueryRow("SELECT data FROM device_codes WHERE signature = ?", deviceCode).Scan(&data)
	if err == sql.ErrNoRows {
		// If not found, try extracting the signature part (after the last dot)
		parts := strings.Split(deviceCode, ".")
		if len(parts) > 1 {
			signature := parts[len(parts)-1]
			s.logger.Debugf("🔍 SQLiteStore.GetDeviceCodeSession: trying signature part: %s", signature)
			err = s.db.QueryRow("SELECT data FROM device_codes WHERE signature = ?", signature).Scan(&data)
		}
	}

	if err == sql.ErrNoRows {
		s.logger.Errorf("❌ SQLiteStore.GetDeviceCodeSession: device code not found: %s", deviceCode)
		return nil, fosite.ErrInvalidRequest
	}
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.GetDeviceCodeSession: database error: %v", err)
		return nil, err
	}

	s.logger.Debugf("✅ SQLiteStore.GetDeviceCodeSession: found device code data")
	return s.UnmarshalDeviceRequestWithClientID([]byte(data))
}

func (s *SQLiteStore) CreateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	s.logger.Debugf("🔍 SQLiteStore.CreateDeviceCodeSession: storing device code: %s", deviceCode)

	// Convert to DeviceRequester if needed
	var deviceReq fosite.DeviceRequester
	if dr, ok := request.(fosite.DeviceRequester); ok {
		deviceReq = dr
	} else {
		return fmt.Errorf("request is not a DeviceRequester")
	}

	data, err := types.MarshalDeviceRequestWithClientID(deviceReq)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO device_codes (signature, data) VALUES (?, ?)",
		deviceCode, string(data),
	)
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.CreateDeviceCodeSession: failed to store: %v", err)
	} else {
		s.logger.Debugf("✅ SQLiteStore.CreateDeviceCodeSession: successfully stored device code: %s", deviceCode)
	}
	return err
}

func (s *SQLiteStore) UpdateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	s.logger.Debugf("🔍 SQLiteStore.UpdateDeviceCodeSession: updating device code: %s", deviceCode)

	// Convert to DeviceRequester if needed
	var deviceReq fosite.DeviceRequester
	if dr, ok := request.(fosite.DeviceRequester); ok {
		deviceReq = dr
	} else {
		return fmt.Errorf("request is not a DeviceRequester")
	}

	data, err := types.MarshalDeviceRequestWithClientID(deviceReq)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"UPDATE device_codes SET data = ? WHERE signature = ?",
		string(data), deviceCode,
	)
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.UpdateDeviceCodeSession: failed to update: %v", err)
	} else {
		s.logger.Debugf("✅ SQLiteStore.UpdateDeviceCodeSession: successfully updated device code: %s", deviceCode)
	}
	return err
}

func (s *SQLiteStore) InvalidateDeviceCodeSession(ctx context.Context, signature string) error {
	_, err := s.db.Exec("DELETE FROM device_codes WHERE signature = ?", signature)
	return err
}

func (s *SQLiteStore) GetPendingDeviceAuths(ctx context.Context) (map[string]fosite.Requester, error) {
	rows, err := s.db.Query("SELECT signature, data FROM device_codes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pending := make(map[string]fosite.Requester)
	for rows.Next() {
		var signature string
		var data string
		if err := rows.Scan(&signature, &data); err != nil {
			return nil, err
		}

		deviceReq, err := s.UnmarshalDeviceRequestWithClientID([]byte(data))
		if err != nil {
			return nil, err
		}

		pending[signature] = deviceReq
	}

	return pending, nil
}

func (s *SQLiteStore) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (fosite.DeviceRequester, string, error) {
	var signature string
	var data string
	err := s.db.QueryRow("SELECT signature, data FROM device_codes WHERE user_code = ?", userCode).Scan(&signature, &data)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("device authorization not found for user code: %s", userCode)
	}
	if err != nil {
		return nil, "", err
	}

	deviceReq, err := s.UnmarshalDeviceRequestWithClientID([]byte(data))
	if err != nil {
		return nil, "", err
	}

	return deviceReq, signature, nil
}

func (s *SQLiteStore) CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.DeviceRequester) error {
	s.logger.Debugf("🔍 SQLiteStore.CreateDeviceAuthSession: storing device code: %s, user code: %s", deviceCodeSignature, userCodeSignature)

	data, err := types.MarshalDeviceRequestWithClientID(request)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO device_codes (signature, user_code, data) VALUES (?, ?, ?)",
		deviceCodeSignature, userCodeSignature, string(data),
	)
	if err != nil {
		s.logger.Errorf("❌ SQLiteStore.CreateDeviceAuthSession: failed to store: %v", err)
	} else {
		s.logger.Debugf("✅ SQLiteStore.CreateDeviceAuthSession: successfully stored device code: %s", deviceCodeSignature)
	}
	return err
}

// Helper methods for statistics
func (s *SQLiteStore) GetClientCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetUserCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetAccessTokenCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM access_tokens").Scan(&count)
	return count, err
}

func (s *SQLiteStore) GetRefreshTokenCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	return count, err
}

// Secure client data storage methods
func (s *SQLiteStore) StoreClientSecret(ctx context.Context, clientID string, encryptedSecret string) error {
	_, err := s.db.Exec(
		"UPDATE clients SET encrypted_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		encryptedSecret, clientID,
	)
	return err
}

func (s *SQLiteStore) GetClientSecret(ctx context.Context, clientID string) (string, error) {
	var encryptedSecret string
	err := s.db.QueryRow("SELECT encrypted_secret FROM clients WHERE id = ?", clientID).Scan(&encryptedSecret)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("client secret not found")
	}
	if err != nil {
		return "", err
	}
	return encryptedSecret, nil
}

func (s *SQLiteStore) StoreAttestationConfig(ctx context.Context, clientID string, config *config.ClientAttestationConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"UPDATE clients SET attestation_config = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		string(data), clientID,
	)
	return err
}

func (s *SQLiteStore) GetAttestationConfig(ctx context.Context, clientID string) (*config.ClientAttestationConfig, error) {
	var data string
	err := s.db.QueryRow("SELECT attestation_config FROM clients WHERE id = ?", clientID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("attestation config not found")
	}
	if err != nil {
		return nil, err
	}

	var config config.ClientAttestationConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (s *SQLiteStore) DeleteClientSecret(ctx context.Context, clientID string) error {
	_, err := s.db.Exec(
		"UPDATE clients SET encrypted_secret = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		clientID,
	)
	return err
}

func (s *SQLiteStore) DeleteAttestationConfig(ctx context.Context, clientID string) error {
	_, err := s.db.Exec(
		"UPDATE clients SET attestation_config = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		clientID,
	)
	return err
}

// Trust anchor storage methods
func (s *SQLiteStore) StoreTrustAnchor(ctx context.Context, name string, certificateData []byte) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO trust_anchors (name, certificate_data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
		name, string(certificateData),
	)
	return err
}

func (s *SQLiteStore) GetTrustAnchor(ctx context.Context, name string) ([]byte, error) {
	var data string
	err := s.db.QueryRow("SELECT certificate_data FROM trust_anchors WHERE name = ?", name).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("trust anchor not found")
	}
	if err != nil {
		return nil, err
	}
	return []byte(data), nil
}

func (s *SQLiteStore) ListTrustAnchors(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query("SELECT name FROM trust_anchors ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

func (s *SQLiteStore) DeleteTrustAnchor(ctx context.Context, name string) error {
	result, err := s.db.Exec("DELETE FROM trust_anchors WHERE name = ?", name)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("trust anchor not found")
	}
	return nil
}

// Upstream token mapping methods for proxy mode
func (s *SQLiteStore) StoreUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string, upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO upstream_token_mappings 
		 (proxy_token_signature, upstream_access_token, upstream_refresh_token, upstream_token_type, upstream_expires_in, updated_at) 
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		proxyTokenSignature, upstreamAccessToken, upstreamRefreshToken, upstreamTokenType, upstreamExpiresIn,
	)
	return err
}

func (s *SQLiteStore) GetUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) (upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64, err error) {
	var accessToken, refreshToken, tokenType string
	var expiresIn sql.NullInt64

	err = s.db.QueryRow(
		"SELECT upstream_access_token, upstream_refresh_token, upstream_token_type, upstream_expires_in FROM upstream_token_mappings WHERE proxy_token_signature = ?",
		proxyTokenSignature,
	).Scan(&accessToken, &refreshToken, &tokenType, &expiresIn)

	if err == sql.ErrNoRows {
		return "", "", "", 0, fmt.Errorf("upstream token mapping not found")
	}
	if err != nil {
		return "", "", "", 0, err
	}

	expiresInValue := int64(0)
	if expiresIn.Valid {
		expiresInValue = expiresIn.Int64
	}

	return accessToken, refreshToken, tokenType, expiresInValue, nil
}

func (s *SQLiteStore) DeleteUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) error {
	result, err := s.db.Exec("DELETE FROM upstream_token_mappings WHERE proxy_token_signature = ?", proxyTokenSignature)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("upstream token mapping not found")
	}
	return nil
}

// PAR methods
func (s *SQLiteStore) StorePARRequest(ctx context.Context, request *types.PARRequest) error {
	parametersJSON, err := json.Marshal(request.Parameters)
	if err != nil {
		return fmt.Errorf("failed to marshal PAR parameters: %w", err)
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO par_requests (request_uri, client_id, expires_at, parameters) VALUES (?, ?, ?, ?)",
		request.RequestURI, request.ClientID, request.ExpiresAt, string(parametersJSON),
	)
	return err
}

func (s *SQLiteStore) GetPARRequest(ctx context.Context, requestURI string) (*types.PARRequest, error) {
	var clientID string
	var expiresAt time.Time
	var parametersJSON string

	err := s.db.QueryRow(
		"SELECT client_id, expires_at, parameters FROM par_requests WHERE request_uri = ?",
		requestURI,
	).Scan(&clientID, &expiresAt, &parametersJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("PAR request not found")
	}
	if err != nil {
		return nil, err
	}

	if time.Now().After(expiresAt) {
		// Clean up expired request
		s.db.Exec("DELETE FROM par_requests WHERE request_uri = ?", requestURI)
		return nil, fmt.Errorf("PAR request expired")
	}

	var parameters map[string]string
	if err := json.Unmarshal([]byte(parametersJSON), &parameters); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PAR parameters: %w", err)
	}

	return &types.PARRequest{
		RequestURI: requestURI,
		ClientID:   clientID,
		ExpiresAt:  expiresAt,
		Parameters: parameters,
	}, nil
}

func (s *SQLiteStore) DeletePARRequest(ctx context.Context, requestURI string) error {
	result, err := s.db.Exec("DELETE FROM par_requests WHERE request_uri = ?", requestURI)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("PAR request not found")
	}
	return nil
}

func (s *SQLiteStore) UnmarshalDeviceRequestWithClientID(data []byte) (fosite.DeviceRequester, error) {
	log.Printf("🔍 UnmarshalDeviceRequestWithClientID: starting unmarshal of data (length: %d): %s", len(data), string(data))

	var wrapper types.DeviceRequestWithClientID
	if err := json.Unmarshal(data, &wrapper); err != nil {
		log.Printf("❌ UnmarshalDeviceRequestWithClientID: failed to unmarshal wrapper: %v", err)
		return nil, err
	}

	log.Printf("🔍 UnmarshalDeviceRequestWithClientID: wrapper type: %s, clientID: %s", wrapper.Type, wrapper.ClientID)

	if wrapper.DeviceRequest == nil {
		return nil, fmt.Errorf("DeviceRequest is nil")
	}

	// Set client if we have a client ID
	if wrapper.ClientID != "" {
		client, err := s.GetClient(context.Background(), wrapper.ClientID)
		if err != nil {
			log.Printf("❌ UnmarshalDeviceRequestWithClientID: GetClient error for %s: %v", wrapper.ClientID, err)
			return nil, err
		}
		wrapper.DeviceRequest.Request.Client = client
		log.Printf("✅ UnmarshalDeviceRequestWithClientID: set client %s on device request", wrapper.ClientID)
	}

	log.Printf("✅ UnmarshalDeviceRequestWithClientID: successfully unmarshaled device request")
	return wrapper.DeviceRequest, nil
}

func (s *SQLiteStore) UnmarshalRequestWithClientID(data []byte) (fosite.Requester, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("❌ UnmarshalRequestWithClientID: failed to unmarshal raw: %v", err)
		return nil, err
	}

	clientID, _ := raw["_client_id"].(string)
	typ, _ := raw["_type"].(string)

	delete(raw, "_client_id")
	delete(raw, "_type")

	requestData, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	var request fosite.Requester
	switch typ {
	case "Request":
		// Extract session and client data before unmarshaling the request
		var sessionData interface{}
		if sess, ok := raw["session"]; ok {
			sessionData = sess
			delete(raw, "session")
		}
		var clientData interface{}
		if client, ok := raw["client"]; ok {
			clientData = client
			delete(raw, "client")
		}

		requestData, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}

		var req fosite.Request
		if err := json.Unmarshal(requestData, &req); err != nil {
			log.Printf("❌ UnmarshalRequestWithClientID: failed to unmarshal Request: %v", err)
			return nil, err
		}

		// Handle session separately
		if sessionData != nil {
			sessionBytes, err := json.Marshal(sessionData)
			if err != nil {
				return nil, err
			}
			var session openid.DefaultSession
			if err := json.Unmarshal(sessionBytes, &session); err != nil {
				log.Printf("❌ UnmarshalRequestWithClientID: failed to unmarshal session: %v", err)
				return nil, err
			}
			req.Session = &session
		}

		// Handle client separately if not already set via clientID
		if clientData != nil && clientID == "" {
			clientBytes, err := json.Marshal(clientData)
			if err != nil {
				return nil, err
			}
			var client fosite.DefaultClient
			if err := json.Unmarshal(clientBytes, &client); err != nil {
				log.Printf("❌ UnmarshalRequestWithClientID: failed to unmarshal client: %v", err)
				return nil, err
			}
			req.Client = &client
		}

		request = &req
	case "AccessRequest":
		var req fosite.AccessRequest
		if err := json.Unmarshal(requestData, &req); err != nil {
			log.Printf("❌ UnmarshalRequestWithClientID: failed to unmarshal AccessRequest: %v", err)
			return nil, err
		}
		request = &req
	default:
		return nil, fmt.Errorf("unknown type: %s", typ)
	}

	// Set client if we have a client ID
	if clientID != "" {
		client, err := s.GetClient(context.Background(), clientID)
		if err != nil {
			log.Printf("❌ UnmarshalRequestWithClientID: GetClient error for %s: %v", clientID, err)
			return nil, err
		}
		// Set client on the request
		switch req := request.(type) {
		case *fosite.Request:
			req.Client = client
		case *fosite.AccessRequest:
			req.Client = client
		}
		log.Printf("✅ UnmarshalRequestWithClientID: set client %s on request", clientID)
	}

	// Ensure granted scopes/audience are populated for requests that may have persisted without grants
	getScopesFromSession := func(req fosite.Requester) []string {
		if req == nil {
			return nil
		}
		sess := req.GetSession()
		ds, ok := sess.(*openid.DefaultSession)
		if !ok || ds == nil || ds.Claims == nil || ds.Claims.Extra == nil {
			return nil
		}
		if raw, ok := ds.Claims.Extra["granted_scopes"]; ok {
			switch v := raw.(type) {
			case []string:
				return append([]string{}, v...)
			case []interface{}:
				var scopes []string
				for _, item := range v {
					if s, ok := item.(string); ok {
						scopes = append(scopes, s)
					}
				}
				return scopes
			}
		}
		return nil
	}

	if ar, ok := request.(*fosite.AccessRequest); ok {
		if len(ar.GrantedScope) == 0 && len(ar.Request.RequestedScope) > 0 {
			ar.GrantedScope = append(fosite.Arguments{}, ar.Request.RequestedScope...)
			log.Printf("🔧 UnmarshalRequestWithClientID: backfilled GrantedScope from RequestedScope for client %s", clientID)
		}
		if len(ar.GrantedAudience) == 0 && len(ar.Request.RequestedAudience) > 0 {
			ar.GrantedAudience = append(fosite.Arguments{}, ar.Request.RequestedAudience...)
			log.Printf("🔧 UnmarshalRequestWithClientID: backfilled GrantedAudience from RequestedAudience for client %s", clientID)
		}
		if len(ar.GrantedScope) == 0 && len(ar.Request.RequestedScope) == 0 {
			scopes := getScopesFromSession(ar)
			if len(scopes) == 0 && ar.Client != nil {
				scopes = append([]string{}, ar.Client.GetScopes()...)
			}
			if len(scopes) > 0 {
				ar.Request.RequestedScope = append(fosite.Arguments{}, scopes...)
				ar.GrantedScope = append(fosite.Arguments{}, scopes...)
				log.Printf("🔧 UnmarshalRequestWithClientID: backfilled GrantedScope from session/client scopes for client %s", clientID)
			}
		}
	} else if req, ok := request.(*fosite.Request); ok {
		if len(req.GrantedScope) == 0 && len(req.RequestedScope) > 0 {
			req.GrantedScope = append(fosite.Arguments{}, req.RequestedScope...)
			log.Printf("🔧 UnmarshalRequestWithClientID: backfilled GrantedScope from RequestedScope for client %s", clientID)
		}
		if len(req.GrantedAudience) == 0 && len(req.RequestedAudience) > 0 {
			req.GrantedAudience = append(fosite.Arguments{}, req.RequestedAudience...)
			log.Printf("🔧 UnmarshalRequestWithClientID: backfilled GrantedAudience from RequestedAudience for client %s", clientID)
		}
		if len(req.GrantedScope) == 0 && len(req.RequestedScope) == 0 {
			scopes := getScopesFromSession(req)
			if len(scopes) == 0 && req.Client != nil {
				scopes = append([]string{}, req.Client.GetScopes()...)
			}
			if len(scopes) > 0 {
				req.RequestedScope = append(fosite.Arguments{}, scopes...)
				req.GrantedScope = append(fosite.Arguments{}, scopes...)
				log.Printf("🔧 UnmarshalRequestWithClientID: backfilled GrantedScope from session/client scopes for client %s", clientID)
			}
		}
	}

	log.Printf("✅ UnmarshalRequestWithClientID: successfully unmarshaled request")
	return request, nil
}
