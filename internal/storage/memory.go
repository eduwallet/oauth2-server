package storage

import (
	//  "encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// MemoryStorage implements Storage interface using in-memory maps
type MemoryStorage struct {
	mu                 sync.RWMutex
	authCodes          map[string]*AuthCodeState
	deviceCodes        map[string]*DeviceCodeState
	userCodes          map[string]string // user_code -> device_code mapping
	dynamicClients     map[string]*DynamicClient
	registrationTokens map[string]*RegistrationToken
	tokens             map[string]*TokenState
	sessions           map[string]*SessionState
}

// NewMemoryStorage creates a new in-memory storage instance
func NewMemoryStorage() *MemoryStorage {
	log.Println("NewMemoryStorage: Creating new in-memory storage instance")
	storage := &MemoryStorage{
		authCodes:          make(map[string]*AuthCodeState),
		deviceCodes:        make(map[string]*DeviceCodeState),
		userCodes:          make(map[string]string),
		dynamicClients:     make(map[string]*DynamicClient),
		registrationTokens: make(map[string]*RegistrationToken),
		tokens:             make(map[string]*TokenState),
		sessions:           make(map[string]*SessionState),
	}
	log.Println("NewMemoryStorage: In-memory storage instance created successfully")
	return storage
}

// StoreAuthCode stores an authorization code
func (s *MemoryStorage) StoreAuthCode(code *AuthCodeState) error {
	log.Printf("MemoryStorage: Storing auth code: %s for client: %s", code.Code, code.ClientID)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.authCodes[code.Code] = code
	log.Printf("MemoryStorage: Auth code stored successfully, total codes: %d", len(s.authCodes))
	return nil
}

// GetAuthCode retrieves an authorization code
func (s *MemoryStorage) GetAuthCode(code string) (*AuthCodeState, error) {
	log.Printf("MemoryStorage: Retrieving auth code: %s", code)
	s.mu.RLock()
	defer s.mu.RUnlock()

	authCode, exists := s.authCodes[code]
	if !exists {
		log.Printf("MemoryStorage: Auth code not found: %s", code)
		return nil, fmt.Errorf("auth code not found: %s", code)
	}

	log.Printf("MemoryStorage: Auth code found for client: %s", authCode.ClientID)
	return authCode, nil
}

// DeleteAuthCode removes an authorization code
func (s *MemoryStorage) DeleteAuthCode(code string) error {
	log.Printf("MemoryStorage: Deleting auth code: %s", code)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.authCodes[code]; !exists {
		log.Printf("MemoryStorage: Auth code not found for deletion: %s", code)
		return fmt.Errorf("auth code not found: %s", code)
	}

	delete(s.authCodes, code)
	log.Printf("MemoryStorage: Auth code deleted successfully, remaining codes: %d", len(s.authCodes))
	return nil
}

// StoreDeviceCode stores a device code
func (s *MemoryStorage) StoreDeviceCode(deviceCode *DeviceCodeState) error {
	log.Printf("MemoryStorage: Storing device code: %s with user code: %s for client: %s",
		deviceCode.DeviceCode, deviceCode.UserCode, deviceCode.ClientID)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deviceCodes[deviceCode.DeviceCode] = deviceCode
	s.userCodes[deviceCode.UserCode] = deviceCode.DeviceCode
	log.Printf("MemoryStorage: Device code stored successfully, total device codes: %d", len(s.deviceCodes))
	return nil
}

// GetDeviceCode retrieves a device code
func (s *MemoryStorage) GetDeviceCode(deviceCode string) (*DeviceCodeState, error) {
	log.Printf("MemoryStorage: Retrieving device code: %s", deviceCode)
	s.mu.RLock()
	defer s.mu.RUnlock()

	code, exists := s.deviceCodes[deviceCode]
	if !exists {
		log.Printf("MemoryStorage: Device code not found: %s", deviceCode)
		return nil, fmt.Errorf("device code not found: %s", deviceCode)
	}

	log.Printf("MemoryStorage: Device code found for client: %s, authorized: %t", code.ClientID, code.Authorized)
	return code, nil
}

// GetDeviceCodeByUserCode retrieves a device code by user code
func (s *MemoryStorage) GetDeviceCodeByUserCode(userCode string) (*DeviceCodeState, error) {
	log.Printf("MemoryStorage: Retrieving device code by user code: %s", userCode)
	s.mu.RLock()
	defer s.mu.RUnlock()

	deviceCode, exists := s.userCodes[userCode]
	if !exists {
		log.Printf("MemoryStorage: User code not found: %s", userCode)
		return nil, fmt.Errorf("user code not found: %s", userCode)
	}

	code, exists := s.deviceCodes[deviceCode]
	if !exists {
		log.Printf("MemoryStorage: Device code not found for user code %s: %s", userCode, deviceCode)
		return nil, fmt.Errorf("device code not found for user code %s", userCode)
	}

	log.Printf("MemoryStorage: Device code found for user code: %s, client: %s", userCode, code.ClientID)
	return code, nil
}

// UpdateDeviceCode updates a device code
func (s *MemoryStorage) UpdateDeviceCode(deviceCode *DeviceCodeState) error {
	log.Printf("MemoryStorage: Updating device code: %s", deviceCode.DeviceCode)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.deviceCodes[deviceCode.DeviceCode]; !exists {
		log.Printf("MemoryStorage: Device code not found for update: %s", deviceCode.DeviceCode)
		return fmt.Errorf("device code not found: %s", deviceCode.DeviceCode)
	}

	s.deviceCodes[deviceCode.DeviceCode] = deviceCode
	log.Printf("MemoryStorage: Device code updated successfully, authorized: %t", deviceCode.Authorized)
	return nil
}

// DeleteDeviceCode removes a device code
func (s *MemoryStorage) DeleteDeviceCode(deviceCode string) error {
	log.Printf("MemoryStorage: Deleting device code: %s", deviceCode)
	s.mu.Lock()
	defer s.mu.Unlock()

	code, exists := s.deviceCodes[deviceCode]
	if !exists {
		log.Printf("MemoryStorage: Device code not found for deletion: %s", deviceCode)
		return fmt.Errorf("device code not found: %s", deviceCode)
	}

	delete(s.deviceCodes, deviceCode)
	delete(s.userCodes, code.UserCode)
	log.Printf("MemoryStorage: Device code deleted successfully, remaining device codes: %d", len(s.deviceCodes))
	return nil
}

// StoreDynamicClient stores a dynamic client
func (s *MemoryStorage) StoreDynamicClient(client *DynamicClient) error {
	log.Printf("MemoryStorage: Storing dynamic client: %s (%s)", client.ClientID, client.ClientName)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dynamicClients[client.ClientID] = client
	log.Printf("MemoryStorage: Dynamic client stored successfully, total clients: %d", len(s.dynamicClients))
	return nil
}

// GetDynamicClient retrieves a dynamic client
func (s *MemoryStorage) GetDynamicClient(clientID string) (*DynamicClient, error) {
	log.Printf("MemoryStorage: Retrieving dynamic client: %s", clientID)
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.dynamicClients[clientID]
	if !exists {
		log.Printf("MemoryStorage: Dynamic client not found: %s", clientID)
		return nil, fmt.Errorf("dynamic client not found: %s", clientID)
	}

	log.Printf("MemoryStorage: Dynamic client found: %s (%s)", clientID, client.ClientName)
	return client, nil
}

// UpdateDynamicClient updates a dynamic client
func (s *MemoryStorage) UpdateDynamicClient(client *DynamicClient) error {
	log.Printf("MemoryStorage: Updating dynamic client: %s", client.ClientID)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.dynamicClients[client.ClientID]; !exists {
		log.Printf("MemoryStorage: Dynamic client not found for update: %s", client.ClientID)
		return fmt.Errorf("dynamic client not found: %s", client.ClientID)
	}

	s.dynamicClients[client.ClientID] = client
	log.Printf("MemoryStorage: Dynamic client updated successfully: %s", client.ClientID)
	return nil
}

// DeleteDynamicClient removes a dynamic client
func (s *MemoryStorage) DeleteDynamicClient(clientID string) error {
	log.Printf("MemoryStorage: Deleting dynamic client: %s", clientID)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.dynamicClients[clientID]; !exists {
		log.Printf("MemoryStorage: Dynamic client not found for deletion: %s", clientID)
		return fmt.Errorf("dynamic client not found: %s", clientID)
	}

	delete(s.dynamicClients, clientID)
	log.Printf("MemoryStorage: Dynamic client deleted successfully, remaining clients: %d", len(s.dynamicClients))
	return nil
}

// StoreRegistrationToken stores a registration token
func (s *MemoryStorage) StoreRegistrationToken(token *RegistrationToken) error {
	log.Printf("MemoryStorage: Storing registration token for client: %s", token.ClientID)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.registrationTokens[token.Token] = token
	log.Printf("MemoryStorage: Registration token stored successfully, total tokens: %d", len(s.registrationTokens))
	return nil
}

// GetRegistrationToken retrieves a registration token
func (s *MemoryStorage) GetRegistrationToken(token string) (*RegistrationToken, error) {
	log.Printf("MemoryStorage: Retrieving registration token: %s", token)
	s.mu.RLock()
	defer s.mu.RUnlock()

	regToken, exists := s.registrationTokens[token]
	if !exists {
		log.Printf("MemoryStorage: Registration token not found: %s", token)
		return nil, fmt.Errorf("registration token not found: %s", token)
	}

	log.Printf("MemoryStorage: Registration token found for client: %s", regToken.ClientID)
	return regToken, nil
}

// DeleteRegistrationToken removes a registration token
func (s *MemoryStorage) DeleteRegistrationToken(token string) error {
	log.Printf("MemoryStorage: Deleting registration token: %s", token)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.registrationTokens[token]; !exists {
		log.Printf("MemoryStorage: Registration token not found for deletion: %s", token)
		return fmt.Errorf("registration token not found: %s", token)
	}

	delete(s.registrationTokens, token)
	log.Printf("MemoryStorage: Registration token deleted successfully, remaining tokens: %d", len(s.registrationTokens))
	return nil
}

// StoreToken stores a token
func (s *MemoryStorage) StoreToken(token *TokenState) error {
	log.Printf("MemoryStorage: Storing %s token for client: %s", token.TokenType, token.ClientID)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token.Token] = token
	log.Printf("MemoryStorage: Token stored successfully, total tokens: %d", len(s.tokens))
	return nil
}

// GetToken retrieves a token
func (s *MemoryStorage) GetToken(token string) (*TokenState, error) {
	log.Printf("MemoryStorage: Retrieving token: %s", token)
	s.mu.RLock()
	defer s.mu.RUnlock()

	tokenState, exists := s.tokens[token]
	if !exists {
		log.Printf("MemoryStorage: Token not found: %s", token)
		return nil, fmt.Errorf("token not found: %s", token)
	}

	log.Printf("MemoryStorage: Token found, type: %s, client: %s, active: %t",
		tokenState.TokenType, tokenState.ClientID, tokenState.Active)
	return tokenState, nil
}

// UpdateToken updates a token
func (s *MemoryStorage) UpdateToken(token *TokenState) error {
	log.Printf("MemoryStorage: Updating token for client: %s", token.ClientID)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[token.Token]; !exists {
		log.Printf("MemoryStorage: Token not found for update: %s", token.Token)
		return fmt.Errorf("token not found: %s", token.Token)
	}

	s.tokens[token.Token] = token
	log.Printf("MemoryStorage: Token updated successfully, active: %t", token.Active)
	return nil
}

// DeleteToken removes a token
func (s *MemoryStorage) DeleteToken(token string) error {
	log.Printf("MemoryStorage: Deleting token: %s", token)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[token]; !exists {
		log.Printf("MemoryStorage: Token not found for deletion: %s", token)
		return fmt.Errorf("token not found: %s", token)
	}

	delete(s.tokens, token)
	log.Printf("MemoryStorage: Token deleted successfully, remaining tokens: %d", len(s.tokens))
	return nil
}

// StoreSession stores a session
func (s *MemoryStorage) StoreSession(session *SessionState) error {
	log.Printf("MemoryStorage: Storing session: %s for user: %s", session.SessionID, session.UserID)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.SessionID] = session
	log.Printf("MemoryStorage: Session stored successfully, total sessions: %d", len(s.sessions))
	return nil
}

// GetSession retrieves a session
func (s *MemoryStorage) GetSession(sessionID string) (*SessionState, error) {
	log.Printf("MemoryStorage: Retrieving session: %s", sessionID)
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		log.Printf("MemoryStorage: Session not found: %s", sessionID)
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	log.Printf("MemoryStorage: Session found for user: %s", session.UserID)
	return session, nil
}

// DeleteSession removes a session
func (s *MemoryStorage) DeleteSession(sessionID string) error {
	log.Printf("MemoryStorage: Deleting session: %s", sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[sessionID]; !exists {
		log.Printf("MemoryStorage: Session not found for deletion: %s", sessionID)
		return fmt.Errorf("session not found: %s", sessionID)
	}

	delete(s.sessions, sessionID)
	log.Printf("MemoryStorage: Session deleted successfully, remaining sessions: %d", len(s.sessions))
	return nil
}

// CleanupExpired removes expired entries
func (s *MemoryStorage) CleanupExpired() error {
	log.Println("MemoryStorage: Starting cleanup of expired entries...")
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	// Cleanup expired auth codes
	log.Println("MemoryStorage: Cleaning up expired auth codes...")
	for code, authCode := range s.authCodes {
		if now.After(authCode.ExpiresAt) {
			delete(s.authCodes, code)
			expiredCount++
		}
	}
	log.Printf("MemoryStorage: Removed %d expired auth codes", expiredCount)

	// Cleanup expired device codes
	expiredCount = 0
	log.Println("MemoryStorage: Cleaning up expired device codes...")
	for deviceCode, code := range s.deviceCodes {
		if now.After(code.ExpiresAt) {
			delete(s.deviceCodes, deviceCode)
			delete(s.userCodes, code.UserCode)
			expiredCount++
		}
	}
	log.Printf("MemoryStorage: Removed %d expired device codes", expiredCount)

	// Cleanup expired registration tokens
	expiredCount = 0
	log.Println("MemoryStorage: Cleaning up expired registration tokens...")
	for token, regToken := range s.registrationTokens {
		if now.After(regToken.ExpiresAt) {
			delete(s.registrationTokens, token)
			expiredCount++
		}
	}
	log.Printf("MemoryStorage: Removed %d expired registration tokens", expiredCount)

	// Cleanup expired tokens
	expiredCount = 0
	log.Println("MemoryStorage: Cleaning up expired tokens...")
	for token, tokenState := range s.tokens {
		if now.After(tokenState.ExpiresAt) {
			delete(s.tokens, token)
			expiredCount++
		}
	}
	log.Printf("MemoryStorage: Removed %d expired tokens", expiredCount)

	// Cleanup expired sessions
	expiredCount = 0
	log.Println("MemoryStorage: Cleaning up expired sessions...")
	for sessionID, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, sessionID)
			expiredCount++
		}
	}
	log.Printf("MemoryStorage: Removed %d expired sessions", expiredCount)

	log.Println("MemoryStorage: Cleanup completed successfully")
	return nil
}

// Close closes the storage (no-op for memory storage)
func (s *MemoryStorage) Close() error {
	log.Println("MemoryStorage: Closing memory storage (clearing all data)...")
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear all maps
	s.authCodes = make(map[string]*AuthCodeState)
	s.deviceCodes = make(map[string]*DeviceCodeState)
	s.userCodes = make(map[string]string)
	s.dynamicClients = make(map[string]*DynamicClient)
	s.registrationTokens = make(map[string]*RegistrationToken)
	s.tokens = make(map[string]*TokenState)
	s.sessions = make(map[string]*SessionState)

	log.Println("MemoryStorage: Memory storage closed and cleared successfully")
	return nil
}

// GetStats returns storage statistics
func (s *MemoryStorage) GetStats() map[string]interface{} {
	log.Println("MemoryStorage: Gathering storage statistics...")
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"type":                "memory",
		"auth_codes":          len(s.authCodes),
		"device_codes":        len(s.deviceCodes),
		"user_codes":          len(s.userCodes),
		"dynamic_clients":     len(s.dynamicClients),
		"registration_tokens": len(s.registrationTokens),
		"tokens":              len(s.tokens),
		"sessions":            len(s.sessions),
		"timestamp":           time.Now(),
	}

	log.Printf("MemoryStorage: Statistics gathered - %d auth codes, %d device codes, %d clients, %d tokens, %d sessions",
		len(s.authCodes), len(s.deviceCodes), len(s.dynamicClients), len(s.tokens), len(s.sessions))

	return stats
}
