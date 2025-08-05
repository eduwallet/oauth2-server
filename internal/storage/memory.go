package storage

import (
	"fmt"
	"sync"
	"time"

	"oauth2-server/internal/config"
)

// MemoryStorage implements the Storage interface using in-memory maps
type MemoryStorage struct {
	mu                 sync.RWMutex
	authCodes          map[string]*AuthorizeRequest
	deviceCodes        map[string]*DeviceCodeState
	dynamicClients     map[string]*config.ClientConfig
	registrationTokens map[string]string     // token -> client_id mapping
	tokens             map[string]*TokenInfo // OAuth2 tokens
	sessions           map[string]*Session
}

// NewMemoryStorage creates a new in-memory storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		authCodes:          make(map[string]*AuthorizeRequest),
		deviceCodes:        make(map[string]*DeviceCodeState),
		dynamicClients:     make(map[string]*config.ClientConfig),
		registrationTokens: make(map[string]string),
		tokens:             make(map[string]*TokenInfo),
		sessions:           make(map[string]*Session),
	}
}

// Authorization codes methods
func (m *MemoryStorage) StoreAuthCode(code string, authReq *AuthorizeRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCodes[code] = authReq
	return nil
}

func (m *MemoryStorage) GetAuthCode(code string) (*AuthorizeRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	authReq, exists := m.authCodes[code]
	if !exists {
		return nil, nil
	}
	return authReq, nil
}

func (m *MemoryStorage) DeleteAuthCode(code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.authCodes, code)
	return nil
}

// Device codes methods
func (m *MemoryStorage) StoreDeviceCode(deviceCode string, state *DeviceCodeState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceCodes[deviceCode] = state
	return nil
}

func (m *MemoryStorage) GetDeviceCode(deviceCode string) (*DeviceCodeState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil, nil
	}
	return state, nil
}

func (m *MemoryStorage) GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for deviceCode, state := range m.deviceCodes {
		if state.UserCode == userCode {
			return state, deviceCode, nil
		}
	}
	return nil, "", nil
}

func (m *MemoryStorage) UpdateDeviceCode(deviceCode string, state *DeviceCodeState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceCodes[deviceCode] = state
	return nil
}

func (m *MemoryStorage) DeleteDeviceCode(deviceCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.deviceCodes, deviceCode)
	return nil
}

// Dynamic clients methods
func (m *MemoryStorage) StoreDynamicClient(clientID string, client *config.ClientConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dynamicClients[clientID] = client
	return nil
}

func (m *MemoryStorage) GetDynamicClient(clientID string) (*config.ClientConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, exists := m.dynamicClients[clientID]
	if !exists {
		return nil, nil
	}
	return client, nil
}

func (m *MemoryStorage) DeleteDynamicClient(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.dynamicClients, clientID)
	return nil
}

// Registration tokens methods
func (m *MemoryStorage) StoreRegistrationToken(token, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registrationTokens[token] = clientID
	return nil
}

func (m *MemoryStorage) GetClientIDByRegistrationToken(token string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clientID, exists := m.registrationTokens[token]
	if !exists {
		return "", nil
	}
	return clientID, nil
}

func (m *MemoryStorage) DeleteRegistrationToken(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.registrationTokens, token)
	return nil
}

// OAuth2 Tokens methods
func (m *MemoryStorage) StoreToken(tokenInfo *TokenInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tokenInfo.Token] = tokenInfo
	return nil
}

func (m *MemoryStorage) GetToken(token string) (*TokenInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tokenInfo, exists := m.tokens[token]
	if !exists || tokenInfo == nil {
		return nil, fmt.Errorf("token not found")
	}
	if !tokenInfo.Active || time.Now().After(tokenInfo.ExpiresAt) {
		return nil, fmt.Errorf("token expired or inactive")
	}
	return tokenInfo, nil
}

func (m *MemoryStorage) GetTokensByClientID(clientID string) ([]*TokenInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tokens []*TokenInfo
	for _, tokenInfo := range m.tokens {
		if tokenInfo.ClientID == clientID && tokenInfo.Active {
			tokens = append(tokens, tokenInfo)
		}
	}
	return tokens, nil
}

func (m *MemoryStorage) GetTokensByUserID(userID string) ([]*TokenInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tokens []*TokenInfo
	for _, tokenInfo := range m.tokens {
		if tokenInfo.UserID == userID && tokenInfo.Active {
			tokens = append(tokens, tokenInfo)
		}
	}
	return tokens, nil
}

func (m *MemoryStorage) UpdateTokenStatus(token string, active bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tokenInfo, exists := m.tokens[token]; exists {
		tokenInfo.Active = active
	}
	return nil
}

func (m *MemoryStorage) DeleteToken(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, token)
	return nil
}

func (m *MemoryStorage) DeleteTokensByClientID(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for token, tokenInfo := range m.tokens {
		if tokenInfo.ClientID == clientID {
			delete(m.tokens, token)
		}
	}
	return nil
}

func (m *MemoryStorage) DeleteTokensByUserID(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for token, tokenInfo := range m.tokens {
		if tokenInfo.UserID == userID {
			delete(m.tokens, token)
		}
	}
	return nil
}

// CleanupExpired removes expired entries
func (m *MemoryStorage) CleanupExpired() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Clean up expired auth codes
	for code, authReq := range m.authCodes {
		if now.After(authReq.ExpiresAt) {
			delete(m.authCodes, code)
		}
	}

	// Clean up expired device codes
	for deviceCode, state := range m.deviceCodes {
		if now.After(state.ExpiresAt) {
			delete(m.deviceCodes, deviceCode)
		}
	}

	// Clean up expired tokens
	for token, tokenInfo := range m.tokens {
		if now.After(tokenInfo.ExpiresAt) {
			delete(m.tokens, token)
		}
	}

	// Clean expired sessions
	for sessionID, session := range m.sessions {
		if now.After(session.ExpiresAt) || !session.Active {
			delete(m.sessions, sessionID)
		}
	}

	return nil
}

// Close is a no-op for memory storage
func (m *MemoryStorage) Close() error {
	return nil
}

// Add these methods to your internal/storage/memory.go file

// StoreSession stores a user session
func (m *MemoryStorage) StoreSession(sessionID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session := &Session{
		SessionID: sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		Active:    true,
	}

	m.sessions[sessionID] = session
	return nil
}

// GetSession retrieves a session by session ID
func (m *MemoryStorage) GetSession(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) || !session.Active {
		return nil, fmt.Errorf("session expired or inactive")
	}

	return session, nil
}

// DeleteSession removes a session
func (m *MemoryStorage) DeleteSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionID)
	return nil
}
