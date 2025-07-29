package store

import (
	"errors"
	"sync"
	"time"
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

// TokenStore manages tokens
type TokenStore struct {
	   tokens map[string]*Token
	   mutex  sync.RWMutex
}

// NewTokenStore creates a new token store
func NewTokenStore() *TokenStore {
	   return &TokenStore{
			   tokens: make(map[string]*Token),
	   }
}

// StoreToken stores a token
func (s *TokenStore) StoreToken(tokenString, tokenType, clientID, userID string, scopes []string, expiresAt time.Time) error {
		token := &Token{
			Token:     tokenString,
			TokenType: tokenType,
			ClientID:  clientID,
			UserID:    userID,
			Scopes:    scopes,
			ExpiresAt: expiresAt,
			Revoked:   false,
			CreatedAt: time.Now(),
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
			   Active:    true,
			   IssuedAt:  t.CreatedAt,
			   Issuer:    "oauth2-server",
			   Audience:  []string{"api"},
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
func (s *TokenStore) GetStats() map[string]interface{} {
	   s.mutex.RLock()
	   defer s.mutex.RUnlock()
	   now := time.Now()
	   // Overall stats
	   var active, expired, revoked int
	   // Per token type stats
	   typeStats := make(map[string]map[string]int)
	   for _, token := range s.tokens {
			   ttype := token.TokenType
			   if _, ok := typeStats[ttype]; !ok {
					   typeStats[ttype] = map[string]int{"total": 0, "active": 0, "expired": 0, "revoked": 0}
			   }
			   typeStats[ttype]["total"]++
			   if token.Revoked {
					   revoked++
					   typeStats[ttype]["revoked"]++
			   } else if now.After(token.ExpiresAt) {
					   expired++
					   typeStats[ttype]["expired"]++
			   } else {
					   active++
					   typeStats[ttype]["active"]++
			   }
	   }
	   return map[string]interface{}{
			   "tokens": map[string]int{
					   "total":   len(s.tokens),
					   "active":  active,
					   "expired": expired,
					   "revoked": revoked,
			   },
			   "by_type": typeStats,
	   }
}
