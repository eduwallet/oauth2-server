package store

import (
	"context"
	"errors"
	"oauth2-server/internal/utils"
	"sync"
	"time"

	"github.com/ory/fosite"
)

// Token represents an access or refresh token
type Token struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	Audience  []string  `json:"aud"`
}

// TokenInfo represents token information for validation
type TokenInfo struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
	IssuedAt  time.Time `json:"iat"`
	Issuer    string    `json:"iss"`
	Audience  []string  `json:"aud"`
}

// TokenExchangeRequest represents a token exchange request for auditing
type TokenExchangeRequest struct {
	GrantType          string    `json:"grant_type"`
	Resource           string    `json:"resource,omitempty"`
	Audience           string    `json:"audience,omitempty"`
	Scope              string    `json:"scope,omitempty"`
	RequestedTokenType string    `json:"requested_token_type,omitempty"`
	SubjectToken       string    `json:"subject_token"`
	SubjectTokenType   string    `json:"subject_token_type"`
	ActorToken         string    `json:"actor_token,omitempty"`
	ActorTokenType     string    `json:"actor_token_type,omitempty"`
	ClientID           string    `json:"client_id"`
	Timestamp          time.Time `json:"timestamp"`
}

// TokenExchangeResponse represents a token exchange response for auditing
type TokenExchangeResponse struct {
	AccessToken      string    `json:"access_token"`
	IssuedTokenType  string    `json:"issued_token_type"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int64     `json:"expires_in,omitempty"`
	Scope            string    `json:"scope,omitempty"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	Success          bool      `json:"success"`
	ErrorCode        string    `json:"error_code,omitempty"`
	ErrorDescription string    `json:"error_description,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
}

// TokenStats represents token statistics
type TokenStats struct {
	Total    int            `json:"total"`
	Active   int            `json:"active"`
	Expired  int            `json:"expired"`
	Revoked  int            `json:"revoked"`
	ByType   map[string]int `json:"by_type"`
	ByClient map[string]int `json:"by_client"`
}

// TokenStore manages tokens and implements RFC8693Storage
type TokenStore struct {
	tokens            map[string]*Token
	mutex             sync.RWMutex
	Issuer            string
	TokenExpiryConfig map[string]time.Duration
}

// NewTokenStore creates a new token store
func NewTokenStore(issuer string, expiryConfig map[string]time.Duration) *TokenStore {
	return &TokenStore{
		Issuer:            issuer,
		tokens:            make(map[string]*Token),
		TokenExpiryConfig: expiryConfig,
	}
}

// StoreToken stores a token
func (s *TokenStore) StoreToken(tokenString, tokenType, clientID, userID string, scopes []string, audience []string) error {
	if !utils.Contains(audience, clientID) {
		audience = append(audience, clientID)
	}

	expiry, ok := s.TokenExpiryConfig[tokenType]
	if !ok {
		return errors.New("unknown token type for expiry config")
	}
	expiresAt := time.Now().Add(expiry)

	token := &Token{
		Token:     tokenString,
		TokenType: tokenType,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		Revoked:   false,
		CreatedAt: time.Now(),
		Audience:  audience,
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.tokens[token.Token] = token

	return nil
}

// GetToken retrieves a token by value (any type)
func (s *TokenStore) GetToken(token string) (*Token, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	tokenData, exists := s.tokens[token]
	if !exists {
		return nil, errors.New("token not found")
	}
	return tokenData, nil
}

// ValidateToken validates a token and returns token info (any type)
func (s *TokenStore) ValidateToken(token string) (*TokenInfo, error) {
	t, err := s.GetToken(token)
	if err != nil {
		return nil, err
	}

	if t.Revoked {
		return nil, errors.New("token has been revoked")
	}

	if time.Now().After(t.ExpiresAt) {
		return nil, errors.New("token has expired")
	}
	tokenInfo := &TokenInfo{
		Token:     t.Token,
		TokenType: t.TokenType,
		ClientID:  t.ClientID,
		UserID:    t.UserID,
		Scopes:    t.Scopes,
		ExpiresAt: t.ExpiresAt,
		IssuedAt:  t.CreatedAt,
		Issuer:    s.Issuer,
		Audience:  t.Audience,
		Active:    true,
	}
	return tokenInfo, nil
}

// RevokeToken marks a token as revoked

func (s *TokenStore) RevokeToken(token string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	tokenData, exists := s.tokens[token]
	if !exists {
		return errors.New("token not found")
	}
	tokenData.Revoked = true
	return nil
}

// IsTokenValid checks if a token is valid (not expired or revoked)
func (s *TokenStore) IsTokenValid(token string) bool {
	tokenData, err := s.GetToken(token)
	if err != nil {
		return false
	}
	if tokenData.Revoked {
		return false
	}
	if time.Now().After(tokenData.ExpiresAt) {
		return false
	}
	return true
}

// CleanupExpiredTokens removes expired tokens
func (s *TokenStore) CleanupExpiredTokens() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	now := time.Now()
	var expiredTokens []string
	for token, tokenData := range s.tokens {
		if now.After(tokenData.ExpiresAt) {
			expiredTokens = append(expiredTokens, token)
		}
	}
	for _, token := range expiredTokens {
		delete(s.tokens, token)
	}
	return len(expiredTokens)
}

// GetTokensByUser retrieves all tokens for a specific user
func (s *TokenStore) GetTokensByUser(userID string) ([]*Token, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var userTokens []*Token
	for _, token := range s.tokens {
		if token.UserID == userID {
			userTokens = append(userTokens, token)
		}
	}
	return userTokens, nil
}

// GetTokensByClient retrieves all tokens for a specific client
func (s *TokenStore) GetTokensByClient(clientID string) ([]*Token, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var clientTokens []*Token
	for _, token := range s.tokens {
		if token.ClientID == clientID {
			clientTokens = append(clientTokens, token)
		}
	}
	return clientTokens, nil
}

// GetStats returns statistics about stored tokens
func (s *TokenStore) GetStats() *TokenStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := &TokenStats{
		ByType:   make(map[string]int),
		ByClient: make(map[string]int),
	}

	now := time.Now()

	for _, token := range s.tokens {
		stats.Total++

		// Count by type
		stats.ByType[token.TokenType]++

		// Count by client
		stats.ByClient[token.ClientID]++

		// Count by status
		if token.Revoked {
			stats.Revoked++
		} else if token.ExpiresAt.Before(now) {
			stats.Expired++
		} else {
			stats.Active++
		}
	}

	return stats
}

// RFC8693Storage interface implementation

// ValidateSubjectToken validates the subject token and returns token information
func (s *TokenStore) ValidateSubjectToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*TokenInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Find the token in our store
	storedToken, exists := s.tokens[token]
	if !exists {
		return nil, errors.New("subject token not found")
	}

	// Check if token is expired or revoked
	if storedToken.Revoked {
		return nil, errors.New("subject token is revoked")
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, errors.New("subject token is expired")
	}

	// Validate token type if specified
	if tokenType != "" && storedToken.TokenType != tokenType {
		return nil, errors.New("subject token type mismatch")
	}

	// Check if the token type is valid for subject tokens
	validSubjectTypes := []string{"access_token", "refresh_token", "id_token"}
	isValidType := false
	for _, validType := range validSubjectTypes {
		if storedToken.TokenType == validType {
			isValidType = true
			break
		}
	}
	if !isValidType {
		return nil, errors.New("invalid token type for subject token")
	}

	// Convert to TokenInfo
	return &TokenInfo{
		Token:     storedToken.Token,
		TokenType: storedToken.TokenType,
		ClientID:  storedToken.ClientID,
		UserID:    storedToken.UserID,
		Scopes:    storedToken.Scopes,
		ExpiresAt: storedToken.ExpiresAt,
		Active:    true,
		IssuedAt:  storedToken.CreatedAt,
		Issuer:    s.Issuer,
		Audience:  storedToken.Audience,
	}, nil
}
