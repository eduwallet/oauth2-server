package store

import (
	"context"
	"errors"
	"log"
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

// TokenStore manages tokens
type TokenStore struct {
	tokens              map[string]*Token
	mutex               sync.RWMutex
	Issuer              string
	TokenExpiryConfig   map[string]time.Duration // e.g. {"access_token": 1 * time.Hour, "refresh_token": 24 * time.Hour}
	fositeAccessTokens  map[string]fosite.Requester
	fositeRefreshTokens map[string]fosite.Requester
	fositeMutex         sync.RWMutex
}

// NewTokenStore creates a new token store
func NewTokenStore(issuer string, expiryConfig map[string]time.Duration) *TokenStore {
	log.Printf("[DEBUG] TokenStore.NewTokenStore called with issuer=%s", issuer)
	return &TokenStore{
		Issuer:              issuer,
		tokens:              make(map[string]*Token),
		TokenExpiryConfig:   expiryConfig,
		fositeAccessTokens:  make(map[string]fosite.Requester),
		fositeRefreshTokens: make(map[string]fosite.Requester),
	}
}

// StoreToken stores a token
func (s *TokenStore) StoreToken(tokenString, tokenType, clientID, userID string, scopes []string, audience []string) error {
	log.Printf("[DEBUG] TokenStore.StoreToken called with tokenString=%s, tokenType=%s, clientID=%s, userID=%s", tokenString, tokenType, clientID, userID)
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
	log.Printf("[DEBUG] TokenStore.GetToken called with token=%s", token)
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
	log.Printf("[DEBUG] TokenStore.ValidateToken called with token=%s", token)
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
	log.Printf("[DEBUG] TokenStore.RevokeToken called with token=%s", token)
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
	log.Printf("[DEBUG] TokenStore.IsTokenValid called with token=%s", token)
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
	log.Printf("[DEBUG] TokenStore.CleanupExpiredTokens called")
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
	log.Printf("[DEBUG] TokenStore.GetTokensByUser called with userID=%s", userID)
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
	log.Printf("[DEBUG] TokenStore.GetTokensByClient called with clientID=%s", clientID)
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
	log.Printf("[DEBUG] TokenStore.GetStats called")
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

// --- Fosite-compatible session methods ---
func (s *TokenStore) CreateAccessTokenSession(ctx context.Context, signature string, requester fosite.Requester) error {
	log.Printf("[DEBUG] TokenStore.CreateAccessTokenSession called with signature=%s", signature)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()

	log.Printf("[DEBUG] TokenStore.CreateAccessTokenSession: storing signature %s", signature)
	log.Printf("[DEBUG] TokenStore.CreateAccessTokenSession: storing requester %v", requester)
	log.Printf("[DEBUG] TokenStore.CreateAccessTokenSession: subject %s", requester.GetSession().GetSubject())
	log.Printf("[DEBUG] TokenStore.CreateAccessTokenSession: scopes %v", requester.GetRequestedScopes())
	log.Printf("[DEBUG] TokenStore.CreateAccessTokenSession: audience %v", requester.GetRequestedAudience())

	s.fositeAccessTokens[signature] = requester
	return nil
}

func (s *TokenStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] TokenStore.GetAccessTokenSession called with signature=%s", signature)
	s.fositeMutex.RLock()
	defer s.fositeMutex.RUnlock()
	req, ok := s.fositeAccessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	// Optionally, set session fields if needed
	return req, nil
}

func (s *TokenStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	log.Printf("[DEBUG] TokenStore.DeleteAccessTokenSession called with signature=%s", signature)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	delete(s.fositeAccessTokens, signature)
	return nil
}

func (s *TokenStore) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, requester fosite.Requester) error {
	log.Printf("[DEBUG] TokenStore.CreateRefreshTokenSession called with signature=%s, accessSignature=%s", signature, accessSignature)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	s.fositeRefreshTokens[signature] = requester
	return nil
}

// RotateRefreshToken implements RefreshTokenStorage interface. Add your logic as needed.
func (s *TokenStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	log.Printf("[DEBUG] TokenStore.RotateRefreshToken called with requestID=%s, refreshTokenSignature=%s", requestID, refreshTokenSignature)
	return nil
}

func (s *TokenStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] TokenStore.GetRefreshTokenSession called with signature=%s", signature)
	s.fositeMutex.RLock()
	defer s.fositeMutex.RUnlock()
	req, ok := s.fositeRefreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	// Optionally, set session fields if needed
	return req, nil
}

func (s *TokenStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	log.Printf("[DEBUG] TokenStore.DeleteRefreshTokenSession called with signature=%s", signature)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	delete(s.fositeRefreshTokens, signature)
	return nil
}

// --- Fosite OIDC, PKCE, Code, and Revocation stubs ---
// These are required for full Fosite compatibility. In-memory stubs for now.

// --- Authorization Code ---
func (s *TokenStore) CreateAuthorizeCodeSession(ctx context.Context, signature string, requester fosite.Requester) error {
	log.Printf("[DEBUG] TokenStore.CreateAuthorizeCodeSession called with signature=%s", signature)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	if s.fositeAccessTokens == nil {
		s.fositeAccessTokens = make(map[string]fosite.Requester)
	}
	s.fositeAccessTokens[signature] = requester
	return nil
}

func (s *TokenStore) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] TokenStore.GetAuthorizeCodeSession called with signature=%s", signature)
	s.fositeMutex.RLock()
	defer s.fositeMutex.RUnlock()
	req, ok := s.fositeAccessTokens[signature]
	if !ok {
		log.Printf("[ERROR] TokenStore.GetAuthorizeCodeSession: code %s not found", signature)
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *TokenStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	log.Printf("[DEBUG] TokenStore.InvalidateAuthorizeCodeSession called with signature=%s", signature)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	delete(s.fositeAccessTokens, signature)
	return nil
}

// --- PKCE ---
func (s *TokenStore) CreatePKCERequestSession(ctx context.Context, code string, requester fosite.Requester) error {
	log.Printf("[DEBUG] TokenStore.CreatePKCERequestSession called with code=%s", code)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	if s.fositeAccessTokens == nil {
		s.fositeAccessTokens = make(map[string]fosite.Requester)
	}
	s.fositeAccessTokens[code] = requester
	return nil
}

func (s *TokenStore) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] TokenStore.GetPKCERequestSession called with code=%s", code)
	s.fositeMutex.RLock()
	defer s.fositeMutex.RUnlock()
	req, ok := s.fositeAccessTokens[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *TokenStore) DeletePKCERequestSession(ctx context.Context, code string) error {
	log.Printf("[DEBUG] TokenStore.DeletePKCERequestSession called with code=%s", code)
	// s.fositeMutex.Lock()
	// defer s.fositeMutex.Unlock()
	// delete(s.fositeAccessTokens, code)
	return nil
}

// --- OIDC ---
func (s *TokenStore) CreateOpenIDConnectSession(ctx context.Context, code string, requester fosite.Requester) error {
	log.Printf("[DEBUG] TokenStore.CreateOpenIDConnectSession called with code=%s", code)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	log.Printf("[DEBUG] TokenStore.CreateOpenIDConnectSession: storing code %s", code)
	log.Printf("[DEBUG] TokenStore.CreateOpenIDConnectSession: storing requester %v", requester)
	log.Printf("[DEBUG] TokenStore.CreateOpenIDConnectSession: subject %s", requester.GetSession().GetSubject())
	log.Printf("[DEBUG] TokenStore.CreateOpenIDConnectSession: scopes %v", requester.GetRequestedScopes())
	log.Printf("[DEBUG] TokenStore.CreateOpenIDConnectSession: audience %v", requester.GetRequestedAudience())
	if s.fositeAccessTokens == nil {
		s.fositeAccessTokens = make(map[string]fosite.Requester)
	}
	s.fositeAccessTokens[code] = requester
	return nil
}

func (s *TokenStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	log.Printf("[DEBUG] TokenStore.GetOpenIDConnectSession called with authorizeCode=%s", authorizeCode)
	s.fositeMutex.RLock()
	defer s.fositeMutex.RUnlock()
	req, ok := s.fositeAccessTokens[authorizeCode]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *TokenStore) DeleteOpenIDConnectSession(ctx context.Context, code string) error {
	log.Printf("[DEBUG] TokenStore.DeleteOpenIDConnectSession called with code=%s", code)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	delete(s.fositeAccessTokens, code)
	return nil
}

// --- Token Revocation ---
func (s *TokenStore) RevokeRefreshToken(ctx context.Context, id string) error {
	log.Printf("[DEBUG] TokenStore.RevokeRefreshToken called with id=%s", id)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	delete(s.fositeRefreshTokens, id)
	return nil
}

func (s *TokenStore) RevokeAccessToken(ctx context.Context, id string) error {
	log.Printf("[DEBUG] TokenStore.RevokeAccessToken called with id=%s", id)
	s.fositeMutex.Lock()
	defer s.fositeMutex.Unlock()
	delete(s.fositeAccessTokens, id)
	return nil
}

// --- Fosite Introspection methods ---
// These are required for Fosite's token introspection interface.
func (s *TokenStore) GetAccessTokenSessionBySignature(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] TokenStore.GetAccessTokenSessionBySignature called with signature=%s", signature)
	s.fositeMutex.RLock()
	defer s.fositeMutex.RUnlock()
	req, ok := s.fositeAccessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *TokenStore) GetRefreshTokenSessionBySignature(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] TokenStore.GetRefreshTokenSessionBySignature called with signature=%s", signature)
	s.fositeMutex.RLock()
	defer s.fositeMutex.RUnlock()
	req, ok := s.fositeRefreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

// --- Fosite Client Assertion JWT (RFC 7523) ---
// This is required for Fosite's Storage interface if JWT client assertion is enabled.
func (s *TokenStore) ClientAssertionJWTValid(ctx context.Context, jti string) (err error) {
	log.Printf("[DEBUG] TokenStore.ClientAssertionJWTValid called with jti=%s", jti)
	return nil
}

// --- SetClientAssertionJWT (RFC 7523) ---
// This is required for Fosite's Storage interface if JWT client assertion is enabled.
func (s *TokenStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	log.Printf("[DEBUG] TokenStore.SetClientAssertionJWT called with jti=%s, exp=%v", jti, exp)
	return nil
}

func (s *TokenStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	log.Printf("[DEBUG] TokenStore.IsJWTUsed called with jti=%s", jti)
	return false, nil
}
func (s *TokenStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	log.Printf("[DEBUG] TokenStore.MarkJWTUsedForTime called with jti=%s, exp=%v", jti, exp)
	return nil
}
func (s *TokenStore) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	log.Printf("[DEBUG] TokenStore.CreatePARSession called with requestURI=%s", requestURI)
	return nil
}
func (s *TokenStore) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	log.Printf("[DEBUG] TokenStore.GetPARSession called with requestURI=%s", requestURI)
	return nil, fosite.ErrNotFound
}
func (s *TokenStore) DeletePARSession(ctx context.Context, requestURI string) error {
	log.Printf("[DEBUG] TokenStore.DeletePARSession called with requestURI=%s", requestURI)
	return nil
}
